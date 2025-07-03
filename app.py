from flask import Flask, request, jsonify
from curl_cffi import requests
from urllib.parse import parse_qs, urlparse, urlencode
import re
import time
import json
import uuid
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import pickle
import random
from pathlib import Path
from bs4 import BeautifulSoup
import PyPDF2
import io
import logging
import threading
import base64

# Carregar variáveis de ambiente
load_dotenv()

# Configuração do Flask
app = Flask(__name__)

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuração do Bubble - Agora vem de variável de ambiente
BUBBLE_API_ENDPOINT = os.environ.get('BUBBLE_API_ENDPOINT', '')

# Outras configurações de ambiente
DEBUG_MODE = os.environ.get('DEBUG_MODE', 'False').lower() == 'true'
CACHE_COOKIES = os.environ.get('CACHE_COOKIES', 'True').lower() == 'true'
SAVE_LOG = os.environ.get('SAVE_LOG', 'False').lower() == 'true'

class PJeSSoAutomatorAPI:
    """Versão API do PJeSSoAutomator"""
    
    def __init__(self, verbose=False, save_log=False, cache_cookies=True):
        # Usar curl_cffi com impersonate específico
        self.session = requests.Session(impersonate="chrome120")
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'DNT': '1',
            'Sec-GPC': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Priority': 'u=0, i'
        })
        
        # Variáveis para armazenar dados entre requisições
        self.jsession_id = None
        self.state = None
        self.session_code = None
        self.execution = None
        self.tab_id = None
        self.access_token = None
        self.refresh_token = None
        self.id_token = None
        self.auth_code = None
        self.session_state = None
        self.verbose = verbose
        self.request_count = 0
        
        # Configurações de cache
        self.cache_cookies = cache_cookies
        self.cookies_cache_file = "pje_cookies_cache.pkl"
        self.token_cache_file = "pje_tokens_cache.pkl"
        
        # Armazenar documentos baixados
        self.documentos_texto = {}
        
        # Log simplificado para API
        self.log_entries = []
        
        # Carregar cache ao inicializar
        if self.cache_cookies:
            self.load_cached_data()
    
    def save_cached_data(self):
        """Salva cookies e tokens em cache"""
        if not self.cache_cookies:
            return
            
        try:
            # Salvar cookies
            cookies_data = {
                'cookies': [],
                'timestamp': datetime.now().isoformat(),
                'jsession_id': self.jsession_id
            }
            
            # Para curl_cffi, acessar cookies pode ser diferente
            try:
                for cookie_name, cookie_value in self.session.cookies.items():
                    cookie_data = {
                        'name': cookie_name,
                        'value': cookie_value,
                        'domain': '',  # curl_cffi pode não expor todos os detalhes
                        'path': '/',
                        'secure': True,
                        'expires': None
                    }
                    cookies_data['cookies'].append(cookie_data)
            except:
                # Se falhar, pelo menos salvar o JSESSIONID
                if self.jsession_id:
                    cookie_data = {
                        'name': 'JSESSIONID',
                        'value': self.jsession_id,
                        'domain': '.pje.trt7.jus.br',
                        'path': '/',
                        'secure': True,
                        'expires': None
                    }
                    cookies_data['cookies'].append(cookie_data)
            
            with open(self.cookies_cache_file, 'wb') as f:
                pickle.dump(cookies_data, f)
            
            # Salvar tokens se existirem
            if self.access_token:
                tokens_data = {
                    'access_token': self.access_token,
                    'refresh_token': self.refresh_token,
                    'id_token': self.id_token,
                    'timestamp': datetime.now().isoformat(),
                    'auth_code': self.auth_code,
                    'session_state': self.session_state
                }
                
                with open(self.token_cache_file, 'wb') as f:
                    pickle.dump(tokens_data, f)
                    
            logger.info(f"Cache salvo: {len(cookies_data['cookies'])} cookies")
            
        except Exception as e:
            logger.warning(f"Erro ao salvar cache: {e}")
    
    def load_cached_data(self):
        """Carrega cookies e tokens do cache se válidos"""
        if not self.cache_cookies:
            return False
            
        try:
            # Carregar cookies
            if os.path.exists(self.cookies_cache_file):
                with open(self.cookies_cache_file, 'rb') as f:
                    cookies_data = pickle.load(f)
                
                # Verificar se o cache não é muito antigo (1 hora)
                cache_time = datetime.fromisoformat(cookies_data['timestamp'])
                if datetime.now() - cache_time < timedelta(hours=1):
                    
                    valid_cookies = 0
                    for cookie_data in cookies_data['cookies']:
                        # Verificar se o cookie não expirou
                        if cookie_data['expires'] is None or cookie_data['expires'] > time.time():
                            # Para curl_cffi, pode ser necessário adicionar cookies de forma diferente
                            try:
                                self.session.cookies.set(
                                    cookie_data['name'],
                                    cookie_data['value']
                                )
                                valid_cookies += 1
                            except:
                                # Se falhar, pelo menos tentar guardar o valor
                                if cookie_data['name'] == 'JSESSIONID':
                                    self.jsession_id = cookie_data['value']
                    
                    self.jsession_id = cookies_data.get('jsession_id')
                    logger.info(f"Cache carregado: {valid_cookies} cookies válidos")
                    
                    # Carregar tokens se existirem
                    if os.path.exists(self.token_cache_file):
                        with open(self.token_cache_file, 'rb') as f:
                            tokens_data = pickle.load(f)
                        
                        # Verificar se os tokens não são muito antigos (15 minutos para ser mais seguro)
                        token_time = datetime.fromisoformat(tokens_data['timestamp'])
                        if datetime.now() - token_time < timedelta(minutes=15):
                            self.access_token = tokens_data.get('access_token')
                            self.refresh_token = tokens_data.get('refresh_token')
                            self.id_token = tokens_data.get('id_token')
                            self.auth_code = tokens_data.get('auth_code')
                            self.session_state = tokens_data.get('session_state')
                            logger.info(f"Tokens em cache carregados")
                            return True
                        else:
                            logger.info("Tokens expirados no cache")
                    
                    return valid_cookies > 0
                else:
                    logger.info("Cache expirado, será renovado")
                    
        except Exception as e:
            logger.warning(f"Erro ao carregar cache: {e}")
            
        return False
    
    def clear_cache(self):
        """Limpa o cache de cookies e tokens"""
        try:
            if os.path.exists(self.cookies_cache_file):
                os.remove(self.cookies_cache_file)
            if os.path.exists(self.token_cache_file):
                os.remove(self.token_cache_file)
            logger.info("Cache limpo")
        except Exception as e:
            logger.warning(f"Erro ao limpar cache: {e}")
    
    def is_authenticated_pje(self):
        """Verifica se já está autenticado no PJe"""
        if not self.jsession_id:
            return False
            
        try:
            # Tenta acessar uma página que requer autenticação
            response = self.session.get(
                "https://pje.trt7.jus.br/pjekz/",
                allow_redirects=False,
                timeout=10
            )
            
            # Se retornar 200, está autenticado
            if response.status_code == 200:
                logger.info("Já autenticado no PJe (cache válido)")
                return True
            
        except Exception as e:
            logger.warning(f"Erro na verificação de autenticação: {e}")
            
        return False
    
    def is_token_valid(self):
        """Verifica se o access token ainda é válido"""
        if not self.access_token:
            return False
            
        try:
            response = self.session.get(
                "https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect/userinfo",
                headers={'Authorization': f'bearer {self.access_token}'},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Access token ainda válido")
                return True
            else:
                logger.info(f"Token inválido: Status {response.status_code}")
                
        except Exception as e:
            logger.warning(f"Erro na verificação do token: {e}")
            
        return False
    
    def renovar_token_se_necessario(self):
        """Verifica e renova o token se necessário"""
        if not self.is_token_valid():
            logger.info("Token inválido, renovando...")
            # Limpar token atual
            self.access_token = None
            self.refresh_token = None
            self.auth_code = None
            
            # Tentar obter novo token
            if self.fluxo_obter_token_portal():
                logger.info("Token renovado com sucesso")
                return True
            else:
                logger.error("Falha ao renovar token")
                return False
        return True
    
    def make_request(self, method, url, description="", **kwargs):
        """Wrapper para fazer requisições com logging"""
        self.request_count += 1
        
        try:
            response = self.session.request(method, url, **kwargs)
            
            # Log simplificado
            self.log_entries.append({
                'request_number': self.request_count,
                'description': description,
                'method': method,
                'url': url,
                'status_code': response.status_code,
                'timestamp': datetime.now().isoformat()
            })
            
            if self.verbose:
                logger.debug(f"#{self.request_count} {method} {url} - Status: {response.status_code}")
            
            self.extract_cookies_from_response(response)
            
            return response
            
        except Exception as e:
            logger.error(f"Erro na requisição {method} {url}: {e}")
            raise
        
    def extract_cookies_from_response(self, response):
        """Extrai cookies da resposta - curl_cffi gerencia automaticamente."""
        if response is None:
            return
            
        # curl_cffi já gerencia cookies automaticamente na session
        # Apenas extrair valores específicos se necessário
        try:
            # Verificar se há cookies na resposta
            if hasattr(response, 'cookies'):
                for key, value in response.cookies.items():
                    if key == 'JSESSIONID':
                        self.jsession_id = value
                        if self.verbose:
                            logger.debug(f"[COOKIE] JSESSIONID atualizado: {value[:20]}...")
        except Exception as e:
            # Se falhar, tentar extrair do header Set-Cookie
            set_cookie_headers = response.headers.get('set-cookie', '')
            if set_cookie_headers and 'JSESSIONID' in set_cookie_headers:
                match = re.search(r'JSESSIONID=([^;]+)', set_cookie_headers)
                if match:
                    self.jsession_id = match.group(1)
                    if self.verbose:
                        logger.debug(f"[COOKIE] JSESSIONID extraído do header: {self.jsession_id[:20]}...")
            
    def extract_session_info_from_html(self, html_content):
        """Extrai informações de sessão do HTML"""
        session_code_match = re.search(r'session_code=([^&"]+)', html_content)
        if session_code_match:
            self.session_code = session_code_match.group(1)
            logger.debug(f"Session code extraído: {self.session_code}")
            
        execution_match = re.search(r'execution=([^&"]+)', html_content)
        if execution_match:
            self.execution = execution_match.group(1)
            logger.debug(f"Execution extraído: {self.execution}")
            
        tab_id_match = re.search(r'tab_id=([^&"]+)', html_content)
        if tab_id_match:
            self.tab_id = tab_id_match.group(1)
            logger.debug(f"Tab ID extraído: {self.tab_id}")
            
    def extract_state_from_url(self, url):
        """Extrai o state de uma URL"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if 'state' in query_params:
            return query_params['state'][0]
        return None
        
    def extract_auth_code_from_url(self, url):
        """Extrai o código de autorização de uma URL"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if 'code' in query_params:
            return query_params['code'][0]
        return None
        
    def extract_param_from_url(self, url, param_name):
        """Extrai um parâmetro específico de uma URL"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if param_name in query_params:
            return query_params[param_name][0]
        return None
        
    def extract_param_from_fragment(self, fragment, param_name):
        """Extrai um parâmetro específico de um fragment de URL"""
        params = parse_qs(fragment)
        if param_name in params:
            return params[param_name][0]
        return None
        
    def humanize_delay(self, min_seconds=2, max_seconds=8):
        """Gera delay aleatório para simular comportamento humano"""
        delay = random.uniform(min_seconds, max_seconds)
        time.sleep(delay)
        
    def fluxo_autenticacao_pje(self, username, password):
        """Fluxo otimizado de autenticação PJe"""
        logger.info("Iniciando autenticação PJe...")
        
        # Verificar se já está autenticado
        if self.is_authenticated_pje():
            logger.info("Pulando autenticação PJe - já autenticado")
            return True
            
        # 1. Login inicial
        url = "https://pje.trt7.jus.br/primeirograu/login.seam"
        response1 = self.make_request(
            'GET', url,
            description="Login inicial PJe",
            headers={'Sec-Fetch-Site': 'none'}
        )
        
        if 'JSESSIONID' in response1.cookies:
            self.jsession_id = response1.cookies['JSESSIONID']
        
        self.humanize_delay(1, 3)
        
        # 2. Authenticate SSO
        url = "https://pje.trt7.jus.br/primeirograu/authenticateSSO.seam"
        response2 = self.make_request(
            'GET', url,
            description="Authenticate SSO",
            headers={
                'Referer': 'https://pje.trt7.jus.br/primeirograu/login.seam',
                'Sec-Fetch-Site': 'same-origin'
            },
            allow_redirects=False
        )
        
        if response2.status_code == 302:
            location = response2.headers.get('location', '')
            self.state = self.extract_state_from_url(location)
            
            if location:
                response3 = self.make_request(
                    'GET', location,
                    description="Página de login Keycloak",
                    headers={'Sec-Fetch-Site': 'cross-site'}
                )
                self.extract_session_info_from_html(response3.text)
        
        self.humanize_delay(1, 3)
        
        # 3. Submit login
        if not self.session_code or not self.execution:
            raise Exception("Session code ou execution não encontrados")
            
        url = "https://sso.cloud.pje.jus.br/auth/realms/pje/login-actions/authenticate"
        params = {
            'session_code': self.session_code,
            'execution': self.execution,
            'client_id': 'pje-trt07-1g',
            'tab_id': self.tab_id or 'To8V5ndD02I'
        }
        
        data = {
            'username': username,
            'password': password,
            'credentialId': '',
            'pjeoffice-code': '',
            'phrase': ''
        }
        
        response4 = self.make_request(
            'POST', url,
            description="Submit credenciais",
            params=params,
            data=data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': 'https://sso.cloud.pje.jus.br',
                'Sec-Fetch-Site': 'same-origin'
            },
            allow_redirects=False
        )
        
        # Seguir redirecionamentos
        redirect_count = 0
        current_response = response4
        
        while current_response.status_code in [302, 303] and redirect_count < 3:
            redirect_count += 1
            location = current_response.headers.get('location', '')
            
            if 'authenticateSSO.seam' in location:
                callback_response = self.make_request(
                    'GET', location,
                    description="Callback autenticação",
                    headers={'Sec-Fetch-Site': 'cross-site'}
                )
                break
            else:
                current_response = self.make_request(
                    'GET', location,
                    description=f"Redirecionamento #{redirect_count}",
                    headers={'Sec-Fetch-Site': 'same-origin'},
                    allow_redirects=False
                )
        
        # Salvar cache após autenticação bem-sucedida
        self.save_cached_data()
        
        return True
    
    def fluxo_obter_token_portal(self, force_new=False):
        """Fluxo otimizado para obter token do portal"""
        logger.info("Obtendo token do portal...")
        
        # Se não forçar novo token, verificar se já tem token válido
        if not force_new and self.is_token_valid():
            logger.info("Token ainda válido - pulando obtenção")
            return True
            
        # 1. SSO auth do portal
        state = str(uuid.uuid4())
        nonce = str(uuid.uuid4())
        
        url = "https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect/auth"
        params = {
            'client_id': 'portalexterno-frontend',
            'redirect_uri': 'https://portaldeservicos.pdpj.jus.br/consulta',
            'state': state,
            'response_mode': 'fragment',
            'response_type': 'code',
            'scope': 'openid',
            'nonce': nonce
        }
        
        response = self.make_request(
            'GET', url,
            description="SSO auth portal",
            params=params,
            headers={
                'Referer': 'https://portaldeservicos.pdpj.jus.br/',
                'Sec-Fetch-Site': 'cross-site'
            },
            allow_redirects=False
        )
        
        if response.status_code == 302:
            location = response.headers.get('location', '')
            
            if '#' in location:
                fragment = location.split('#')[1]
                
                if 'error=' in fragment:
                    error = self.extract_param_from_fragment(fragment, 'error')
                    logger.error(f"Erro no SSO: {error}")
                    return False
                    
                self.auth_code = self.extract_param_from_fragment(fragment, 'code')
                self.session_state = self.extract_param_from_fragment(fragment, 'session_state')
        
        if not self.auth_code:
            logger.error("Código de autorização não disponível")
            return False
        
        self.humanize_delay(1, 2)
        
        # 2. Obter access token
        url = "https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect/token"
        data = {
            'code': self.auth_code,
            'grant_type': 'authorization_code',
            'client_id': 'portalexterno-frontend',
            'redirect_uri': 'https://portaldeservicos.pdpj.jus.br/consulta'
        }
        
        response = self.make_request(
            'POST', url,
            description="Obter access token",
            data=data,
            headers={
                'Content-type': 'application/x-www-form-urlencoded',
                'Origin': 'https://portaldeservicos.pdpj.jus.br',
                'Sec-Fetch-Site': 'cross-site'
            }
        )
        
        if response.status_code == 200:
            try:
                token_data = response.json()
                self.access_token = token_data.get('access_token')
                self.refresh_token = token_data.get('refresh_token')
                self.id_token = token_data.get('id_token')
                logger.info("Access token obtido!")
                
                # Salvar tokens no cache
                self.save_cached_data()
                return True
                
            except json.JSONDecodeError:
                logger.error("Erro ao decodificar resposta JSON")
                
        return False
    
    def verificar_userinfo(self):
        """Verifica as informações do usuário"""
        if not self.access_token:
            return False
            
        url = "https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect/userinfo"
        
        response = self.make_request(
            'GET', url,
            description="Verificar userinfo",
            headers={
                'Accept': 'application/json',
                'Authorization': f'bearer {self.access_token}',
                'Origin': 'https://portaldeservicos.pdpj.jus.br',
                'Referer': 'https://portaldeservicos.pdpj.jus.br/',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'cross-site'
            }
        )
        
        return response.status_code == 200
    
    def consultar_processo_detalhado(self, numero_processo):
        """Consulta detalhada de processo"""
        logger.info(f"Consultando processo {numero_processo}...")
        
        if not self.access_token:
            logger.error("Access token não disponível")
            return None
            
        url = f"https://portaldeservicos.pdpj.jus.br/api/v2/processos/{numero_processo}"
        
        response = self.make_request(
            'GET', url,
            description=f"Consultar processo detalhado {numero_processo}",
            headers={
                'Accept': 'application/json, text/plain, */*',
                'skipErrorInterceptor': 'true',
                'Authorization': f'Bearer {self.access_token}',
                'Connection': 'keep-alive',
                'Referer': 'https://portaldeservicos.pdpj.jus.br/consulta',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'Priority': 'u=0',
                'TE': 'trailers'
            }
        )
        
        if response.status_code == 200:
            try:
                processo_info = response.json()
                logger.info("Processo encontrado com detalhes completos!")
                return processo_info
                
            except json.JSONDecodeError:
                logger.error("Erro ao decodificar resposta JSON")
        else:
            logger.error(f"Erro na consulta: Status {response.status_code}")
            
        return None
    
    def extrair_data_distribuicao(self, processo_info):
        """Extrai a data de distribuição do processo"""
        try:
            if processo_info and len(processo_info) > 0:
                dados = processo_info[0]
                tramitacao = dados.get('tramitacaoAtual', {})
                
                # Primeiro tentar pegar da distribuição
                if 'distribuicao' in tramitacao and tramitacao['distribuicao']:
                    data_distribuicao = tramitacao['distribuicao'][0].get('dataHora', '')
                    if data_distribuicao:
                        # Converter para formato YYYYMMDDHHMMSS
                        match = re.match(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})', data_distribuicao)
                        if match:
                            ano, mes, dia, hora, minuto, segundo = match.groups()
                            return f"{ano}{mes}{dia}{hora}{minuto}{segundo}"
                
                # Se não encontrar, tentar data de ajuizamento
                data_ajuizamento = tramitacao.get('dataHoraAjuizamento', '')
                if data_ajuizamento:
                    match = re.match(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})', data_ajuizamento)
                    if match:
                        ano, mes, dia, hora, minuto, segundo = match.groups()
                        return f"{ano}{mes}{dia}{hora}{minuto}{segundo}"
                        
        except Exception as e:
            logger.warning(f"Erro ao extrair data de distribuição: {e}")
        
        # Fallback para data padrão
        return "20220707081114"
    
    def is_html_content(self, content_bytes):
        """Verifica se o conteúdo é HTML baseado no início do arquivo"""
        try:
            text_start = content_bytes[:1000].decode('utf-8', errors='ignore').lower().strip()
            return (text_start.startswith('<!doctype html') or 
                    text_start.startswith('<html') or
                    '<p style=' in text_start or
                    '<div class=' in text_start)
        except:
            return False
    
    def limpar_html(self, html_content):
        """Remove marcações HTML e retorna texto limpo"""
        try:
            # Usar BeautifulSoup para parser HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Remover scripts e styles
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Extrair texto
            texto = soup.get_text()
            
            # Limpar espaços em branco excessivos
            linhas = (linha.strip() for linha in texto.splitlines())
            texto_limpo = '\n'.join(linha for linha in linhas if linha)
            
            return texto_limpo
            
        except Exception as e:
            logger.warning(f"Erro ao limpar HTML: {e}")
            # Fallback: remoção básica de tags HTML
            texto = re.sub(r'<[^>]+>', '', html_content)
            texto = re.sub(r'\s+', ' ', texto).strip()
            return texto
    
    def extrair_texto_pdf(self, pdf_bytes, nome_doc):
        """Extrai texto de um arquivo PDF"""
        try:
            # Criar objeto de arquivo em memória
            pdf_file = io.BytesIO(pdf_bytes)
            
            # Ler PDF
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            
            texto_completo = []
            total_paginas = len(pdf_reader.pages)
            
            logger.info(f"Extraindo texto de PDF: {nome_doc} ({total_paginas} páginas)")
            
            for i, pagina in enumerate(pdf_reader.pages):
                try:
                    texto_pagina = pagina.extract_text()
                    if texto_pagina.strip():
                        texto_completo.append(f"=== PÁGINA {i+1} ===\n{texto_pagina.strip()}")
                except Exception as e:
                    logger.warning(f"Erro ao extrair texto da página {i+1}: {e}")
                    texto_completo.append(f"=== PÁGINA {i+1} ===\n[ERRO NA EXTRAÇÃO]")
            
            if texto_completo:
                return '\n\n'.join(texto_completo)
            else:
                return f"[PDF SEM TEXTO EXTRAÍVEL]\nO PDF {nome_doc} não contém texto extraível ou está protegido."
                
        except Exception as e:
            logger.warning(f"Erro ao processar PDF {nome_doc}: {e}")
            return f"[ERRO NO PROCESSAMENTO PDF]\nNão foi possível extrair texto do PDF: {e}"
    
    def extrair_texto_documento(self, content_bytes, content_type, nome_doc):
        """Extrai texto de documentos HTML ou PDF"""
        try:
            if 'text/plain' in content_type:
                # Se for texto simples, processar como HTML para remover marcações
                try:
                    texto = content_bytes.decode('utf-8')
                    return self.limpar_html(texto)
                except UnicodeDecodeError:
                    try:
                        texto = content_bytes.decode('latin-1')
                        return self.limpar_html(texto)
                    except:
                        logger.warning(f"Erro de codificação para documento texto: {nome_doc}")
                        return None
                        
            elif 'text/html' in content_type or self.is_html_content(content_bytes):
                # Processar como HTML
                try:
                    html_content = content_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        html_content = content_bytes.decode('latin-1')
                    except:
                        logger.warning(f"Erro de codificação para documento HTML: {nome_doc}")
                        return None
                
                return self.limpar_html(html_content)
                
            elif 'application/pdf' in content_type:
                # Processar como PDF
                return self.extrair_texto_pdf(content_bytes, nome_doc)
                
            else:
                logger.warning(f"Tipo de conteúdo não suportado: {content_type} para {nome_doc}")
                # Tentar como texto simples por último recurso
                try:
                    texto = content_bytes.decode('utf-8')
                    return self.limpar_html(texto)
                except:
                    return f"[CONTEÚDO BINÁRIO - TIPO: {content_type}]\nNão foi possível extrair texto deste documento."
                    
        except Exception as e:
            logger.warning(f"Erro na extração de texto de {nome_doc}: {e}")
            return None
    
    def simular_abertura_autos_digitais(self, numero_processo, data_distribuicao):
        """Simula a abertura da aba de autos digitais como no navegador"""
        logger.info("Simulando abertura de autos digitais...")
        
        url = f"https://portaldeservicos.pdpj.jus.br/consulta/autosdigitais?processo={numero_processo}&dataDistribuicao={data_distribuicao}"
        
        # Adicionar cookies de tour se não existirem
        tour_cookies = {
            'tour-primeira-notificacao-%2Fconsulta': 'true',
            'tour-primeira-notificacao-%2Fhome': 'true',
            'tour-primeira-notificacao-%2Fconsulta%2Fautosdigitais': 'true',
            'tour-primeira-notificacao-%2Fpeticao': 'true',
            'tour-primeira-notificacao-%2Fminhas-peticoes': 'true',
            'tour-primeira-notificacao-%2Fcentral-comunicacoes': 'true'
        }
        
        for cookie_name, cookie_value in tour_cookies.items():
            try:
                self.session.cookies.set(cookie_name, cookie_value)
            except:
                pass  # curl_cffi pode ter comportamento diferente
        
        # Delay para simular navegação
        self.humanize_delay(2, 4)
        
        return url

    def baixar_documento_binario(self, numero_processo, documento, data_distribuicao):
        """Baixa o binário de um documento específico e extrai o texto"""
        # Extrair ID do documento do hrefBinario
        href_binario = documento.get('hrefBinario', '')
        if not href_binario:
            logger.warning(f"Documento sem hrefBinario: {documento.get('nome', 'N/A')}")
            return None
        
        # Extrair o ID do documento
        match = re.search(r'/documentos/([^/]+)/binario', href_binario)
        if not match:
            logger.warning(f"Não foi possível extrair ID do documento de: {href_binario}")
            return None
        
        documento_id = match.group(1)
        nome_doc = documento.get('nome', 'Documento sem nome')
        
        logger.info(f"Baixando documento: {nome_doc}")
        
        # Construir URL completa
        url_binario = f"https://portaldeservicos.pdpj.jus.br/api/v2/processos/{numero_processo}/documentos/{documento_id}/binario"
        
        # Referer com a URL de autos digitais
        referer = f"https://portaldeservicos.pdpj.jus.br/consulta/autosdigitais?processo={numero_processo}&dataDistribuicao={data_distribuicao}"
        
        try:
            response = self.make_request(
                'GET', url_binario,
                description=f"Download binário: {nome_doc}",
                headers={
                    'Accept': '*/*',
                    'Referer': referer,
                    'Authorization': f'Bearer {self.access_token}',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'same-origin',
                    'Priority': 'u=4',
                    'TE': 'trailers'
                },
                timeout=30
            )
            
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                content_disposition = response.headers.get('content-disposition', '')
                
                logger.info(f"Download concluído - {len(response.content)} bytes")
                
                # Extrair texto baseado no tipo de conteúdo
                texto_extraido = self.extrair_texto_documento(response.content, content_type, nome_doc)
                
                if texto_extraido is None:
                    logger.error(f"Falha na extração de texto: {nome_doc}")
                    return None
                
                # Para API, vamos converter o binário em base64 para envio
                documento_base64 = base64.b64encode(response.content).decode('utf-8')
                
                resultado = {
                    'sequencia': documento.get('sequencia'),
                    'nome': nome_doc,
                    'tipo': documento.get('tipo', {}).get('nome', 'N/A'),
                    'dataJuntada': documento.get('dataHoraJuntada', 'N/A'),
                    'conteudo': texto_extraido,
                    'tamanho': len(texto_extraido),
                    'url': url_binario,
                    'url_original': href_binario,
                    'content_type': content_type,
                    'tamanho_original': len(response.content),
                    'documento_id': documento_id,
                    'content_disposition': content_disposition,
                    'binario_base64': documento_base64  # Adicionar o binário em base64
                }
                
                return resultado
                
            elif response.status_code == 401:
                logger.error(f"Token expirado durante download: {nome_doc}")
                return None
            elif response.status_code == 403:
                logger.error(f"Acesso negado ao documento: {nome_doc}")
                return None
            elif response.status_code == 404:
                logger.error(f"Documento não encontrado: {nome_doc}")
                return None
            else:
                logger.error(f"Erro ao baixar documento {nome_doc}: Status {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Exceção ao baixar documento {nome_doc}: {e}")
            return None
    
    def baixar_todos_documentos_binario(self, numero_processo, processo_info):
        """Baixa o binário de todos os documentos do processo com extração de texto"""
        logger.info("Baixando binários dos documentos...")
        
        if not processo_info or len(processo_info) == 0:
            logger.error("Informações do processo não disponíveis")
            return []
            
        # Extrair data de distribuição para usar no referer
        data_distribuicao = self.extrair_data_distribuicao(processo_info)
        
        # Simular abertura de autos digitais
        self.simular_abertura_autos_digitais(numero_processo, data_distribuicao)
        
        # Renovar token antes de baixar documentos
        logger.info("Renovando token antes de baixar documentos...")
        if not self.fluxo_obter_token_portal(force_new=True):
            logger.error("Falha ao renovar token")
            return []
        
        # Verificar userinfo
        if not self.verificar_userinfo():
            logger.error("Falha ao verificar userinfo")
            return []
        
        # Fazer nova consulta do processo
        processo_info_atualizado = self.consultar_processo_detalhado(numero_processo)
        if not processo_info_atualizado:
            logger.error("Falha ao consultar processo novamente")
            return []
        
        # Agora sim, baixar os documentos
        dados = processo_info_atualizado[0]
        tramitacao = dados.get('tramitacaoAtual', {})
        documentos = tramitacao.get('documentos', [])
        
        if not documentos:
            logger.info("Nenhum documento encontrado")
            return []
        
        logger.info(f"Encontrados {len(documentos)} documentos total")
        
        documentos_baixados = []
        sucesso = 0
        erro = 0
        
        for i, documento in enumerate(documentos, 1):
            nome_doc = documento.get('nome', f'Documento_{i}')
            tipo_doc = documento.get('tipo', {}).get('nome', 'N/A')
            logger.info(f"[{i}/{len(documentos)}] Processando: {nome_doc} ({tipo_doc})")
            
            # Delay humanizado entre downloads
            if i > 1:
                self.humanize_delay(3, 8)
            
            documento_baixado = self.baixar_documento_binario(numero_processo, documento, data_distribuicao)
            
            if documento_baixado:
                documentos_baixados.append(documento_baixado)
                sucesso += 1
            else:
                erro += 1
                
                # Se muitos erros consecutivos, fazer pausa maior
                if erro > sucesso and erro % 3 == 0:
                    logger.warning("Muitos erros consecutivos. Fazendo pausa maior...")
                    self.humanize_delay(10, 15)
                    
                    # Tentar renovar token
                    logger.info("Tentando renovar token...")
                    self.fluxo_obter_token_portal(force_new=True)
        
        logger.info(f"Download concluído - Sucessos: {sucesso}, Erros: {erro}")
        
        # Armazenar internamente
        self.documentos_texto[numero_processo] = documentos_baixados
        
        return documentos_baixados
    
    def executar_fluxo_completo(self, username, password, numero_processo):
        """Executa o fluxo completo e retorna os dados para a API"""
        try:
            logger.info("Iniciando automação completa...")
            
            # 1. Autenticação PJe
            if not self.fluxo_autenticacao_pje(username, password):
                logger.error("Falha na autenticação PJe")
                return None
            
            # 2. Obter token do portal
            if not self.fluxo_obter_token_portal():
                logger.error("Falha na obtenção do token")
                return None
            
            # 3. Consultar processo detalhado
            if numero_processo and self.access_token:
                processo_info = self.consultar_processo_detalhado(numero_processo)
                if not processo_info:
                    logger.error("Falha na consulta do processo")
                    return None
                
                # 4. Baixar documentos
                documentos_baixados = self.baixar_todos_documentos_binario(numero_processo, processo_info)
                
                # 5. Preparar resposta
                dados = processo_info[0]
                tramitacao = dados.get('tramitacaoAtual', {})
                
                # Extrair informações básicas do processo
                resultado = {
                    'numero_processo': numero_processo,
                    'tribunal': dados.get('siglaTribunal', 'N/A'),
                    'valor_acao': tramitacao.get('valorAcao', 'N/A'),
                    'data_ajuizamento': tramitacao.get('dataHoraAjuizamento', 'N/A'),
                    'classe': tramitacao.get('classe', [{}])[0].get('descricao', 'N/A') if tramitacao.get('classe') else 'N/A',
                    'assunto': tramitacao.get('assunto', [{}])[0].get('descricao', 'N/A') if tramitacao.get('assunto') else 'N/A',
                    'partes': [],
                    'movimentos': [],
                    'documentos': []
                }
                
                # Adicionar partes
                for parte in tramitacao.get('partes', []):
                    resultado['partes'].append({
                        'polo': parte.get('polo', 'N/A'),
                        'nome': parte.get('nome', 'N/A'),
                        'tipo_pessoa': parte.get('tipoPessoa', 'N/A')
                    })
                
                # Adicionar movimentos
                for movimento in tramitacao.get('movimentos', [])[:10]:  # Últimos 10 movimentos
                    resultado['movimentos'].append({
                        'data': movimento.get('dataHora', 'N/A'),
                        'descricao': movimento.get('descricao', 'N/A')
                    })
                
                # Adicionar documentos baixados
                for doc in documentos_baixados:
                    resultado['documentos'].append({
                        'sequencia': doc.get('sequencia'),
                        'nome': doc.get('nome'),
                        'tipo': doc.get('tipo'),
                        'data_juntada': doc.get('dataJuntada'),
                        'conteudo_texto': doc.get('conteudo'),
                        'tamanho_texto': doc.get('tamanho'),
                        'content_type': doc.get('content_type'),
                        'tamanho_original': doc.get('tamanho_original'),
                        'binario_base64': doc.get('binario_base64')  # Incluir o binário
                    })
                
                # Adicionar metadados
                resultado['metadata'] = {
                    'data_processamento': datetime.now().isoformat(),
                    'total_documentos': len(documentos_baixados),
                    'requests_executadas': self.request_count
                }
                
                return resultado
            
            return None
            
        except Exception as e:
            logger.error(f"Erro durante a execução: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

def enviar_dados_bubble(dados_processo):
    """Envia dados processados para o Bubble"""
    if not dados_processo:
        logger.info("Nenhum dado para enviar ao Bubble")
        return False
        
    if not BUBBLE_API_ENDPOINT:
        logger.critical("URL do Endpoint da API do Bubble não definida!")
        return False
        
    logger.info(f"Preparando para enviar dados para o Bubble: {BUBBLE_API_ENDPOINT}")
    
    # Adicionar os dados em formato de lista como esperado pelo Bubble
    payload = [dados_processo]
    
    json_payload = json.dumps(payload, ensure_ascii=False)
    headers = {'Content-Type': 'application/json; charset=utf-8'}
    
    try:
        # Usar requests normal para enviar ao Bubble
        import requests as normal_requests
        response = normal_requests.post(
            BUBBLE_API_ENDPOINT, 
            headers=headers, 
            data=json_payload.encode('utf-8'), 
            timeout=180
        )
        
        if 200 <= response.status_code < 300:
            logger.info(f"Dados enviados com sucesso para o Bubble (Status: {response.status_code})")
            try:
                response_json = response.json()
                logger.info(f"Resposta do Bubble: {response_json}")
            except json.JSONDecodeError:
                logger.warning(f"Resposta do Bubble não era JSON válido: {response.text[:500]}...")
            return True
        else:
            logger.error(f"Erro ao enviar dados para o Bubble (Status: {response.status_code})")
            logger.error(f"Resposta: {response.text[:1000]}...")
            return False
            
    except normal_requests.exceptions.Timeout:
        logger.error(f"Timeout ao enviar dados para o Bubble")
        return False
    except normal_requests.exceptions.RequestException as e:
        logger.error(f"Erro na requisição para o Bubble: {e}")
        return False
    except Exception as e:
        logger.error(f"Erro inesperado ao enviar para o Bubble: {e}", exc_info=True)
        return False

# Rotas da API Flask

@app.route('/health', methods=['GET'])
def health_check():
    """Endpoint de verificação de saúde"""
    return jsonify({
        'status': 'ok',
        'service': 'PJe SSO Automator API',
        'version': '1.0',
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/test', methods=['GET'])
def test_endpoint():
    """Endpoint de teste para verificar conectividade"""
    try:
        # Testar conexão com o PJe usando curl_cffi
        test_session = requests.Session(impersonate="chrome120")
        response = test_session.get('https://pje.trt7.jus.br', timeout=10)
        
        return jsonify({
            'status': 'ok',
            'pje_status': response.status_code,
            'curl_cffi': 'working',
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/process', methods=['POST'])
def process_pje():
    """Endpoint principal para processar consulta PJe"""
    try:
        # Obter dados da requisição
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Dados não fornecidos'
            }), 400
        
        # Validar campos obrigatórios
        required_fields = ['username', 'password', 'numero_processo']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'error': f'Campos obrigatórios faltando: {", ".join(missing_fields)}'
            }), 400
        
        username = data['username']
        password = data['password']
        numero_processo = data['numero_processo']
        
        logger.info(f"Processando requisição para processo {numero_processo}")
        
        # Criar instância do automator
        automator = PJeSSoAutomatorAPI(
            verbose=DEBUG_MODE,
            save_log=SAVE_LOG,
            cache_cookies=CACHE_COOKIES
        )
        
        # Executar fluxo completo
        resultado = automator.executar_fluxo_completo(username, password, numero_processo)
        
        if resultado:
            # Enviar para o Bubble se configurado
            if data.get('enviar_bubble', True):
                bubble_sucesso = enviar_dados_bubble(resultado)
                resultado['bubble_enviado'] = bubble_sucesso
            
            return jsonify({
                'success': True,
                'data': resultado
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Falha ao processar o processo'
            }), 500
            
    except Exception as e:
        logger.error(f"Erro no endpoint process: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/clear-cache', methods=['POST'])
def clear_cache():
    """Endpoint para limpar o cache"""
    try:
        automator = PJeSSoAutomatorAPI()
        automator.clear_cache()
        
        return jsonify({
            'success': True,
            'message': 'Cache limpo com sucesso'
        }), 200
        
    except Exception as e:
        logger.error(f"Erro ao limpar cache: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Função para processar em background (opcional)
def processar_async(username, password, numero_processo, callback_url=None):
    """Processa a requisição de forma assíncrona"""
    try:
        automator = PJeSSoAutomatorAPI(
            verbose=DEBUG_MODE,
            save_log=SAVE_LOG,
            cache_cookies=CACHE_COOKIES
        )
        
        resultado = automator.executar_fluxo_completo(username, password, numero_processo)
        
        if resultado:
            # Enviar para o Bubble
            enviar_dados_bubble(resultado)
            
            # Se houver callback URL, notificar
            if callback_url:
                try:
                    # Usar requests normal para callback
                    import requests as normal_requests
                    normal_requests.post(callback_url, json={
                        'success': True,
                        'numero_processo': numero_processo,
                        'timestamp': datetime.now().isoformat()
                    })
                except:
                    pass
                    
    except Exception as e:
        logger.error(f"Erro no processamento assíncrono: {e}")
        if callback_url:
            try:
                import requests as normal_requests
                normal_requests.post(callback_url, json={
                    'success': False,
                    'numero_processo': numero_processo,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
            except:
                pass

@app.route('/process-async', methods=['POST'])
def process_pje_async():
    """Endpoint para processar de forma assíncrona"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Dados não fornecidos'
            }), 400
        
        # Validar campos obrigatórios
        required_fields = ['username', 'password', 'numero_processo']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'error': f'Campos obrigatórios faltando: {", ".join(missing_fields)}'
            }), 400
        
        username = data['username']
        password = data['password']
        numero_processo = data['numero_processo']
        callback_url = data.get('callback_url')
        
        # Iniciar processamento em thread separada
        thread = threading.Thread(
            target=processar_async,
            args=(username, password, numero_processo, callback_url)
        )
        thread.start()
        
        return jsonify({
            'success': True,
            'message': 'Processamento iniciado',
            'numero_processo': numero_processo
        }), 202
        
    except Exception as e:
        logger.error(f"Erro no endpoint process-async: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    # Configurações da aplicação
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    if not BUBBLE_API_ENDPOINT:
        logger.warning("ATENÇÃO: BUBBLE_API_ENDPOINT não está configurado!")
    
    logger.info(f"Iniciando PJe SSO Automator API na porta {port}")
    logger.info(f"Bubble endpoint configurado: {'Sim' if BUBBLE_API_ENDPOINT else 'Não'}")
    
    # Iniciar servidor Flask
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug
    )
