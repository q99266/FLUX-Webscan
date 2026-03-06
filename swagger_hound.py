#!/usr/bin/env python3
"""
SwaggerHound 集成模块
基于 SwaggerHound 项目: https://github.com/evilc0deooo/SwaggerHound
功能：
- 自动爬取所有 API 链接，对 GET 和 POST 进行请求 (危险请求方法进行跳过)
- 根据文档数据请求类型和参数类型填充默认值
- 支持爬取自定义的模型或对象并填充给参数
"""

import json
import re
import random
import urllib3
import logging
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SwaggerHound:
    """Swagger API 测试模块"""
    
    def __init__(self, session, proxies: dict = None):
        self.session = session
        self.proxies = proxies
        self.findings: List[Dict] = []
        
        self.header_agents = [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Code/1.96.2 Chrome/128.0.6613.186 Electron/32.2.6 Safari/537.36'
        ]
        
        self.black_list_status = [404, 502, 503]
    
    def http_req(self, url: str, method: str = 'get', **kwargs) -> Any:
        """发送HTTP请求"""
        kwargs.setdefault('verify', False)
        kwargs.setdefault('timeout', (10.1, 30.1))
        kwargs.setdefault('allow_redirects', False)
        
        headers = kwargs.get('headers', {})
        headers.setdefault('User-Agent', random.choice(self.header_agents))
        headers.setdefault('Cache-Control', 'max-age=0')
        kwargs['headers'] = headers
        
        if self.proxies:
            kwargs['proxies'] = self.proxies
        
        try:
            conn = getattr(self.session, method)(url, **kwargs)
            return conn
        except Exception as e:
            logger.debug(f"HTTP请求失败 {method} {url}: {e}")
            return None
    
    def check_page(self, url: str) -> int:
        """检查页面类型"""
        try:
            res = self.http_req(url, method='get')
            if not res:
                return 0
            
            if '<html' in res.text:
                return 3  # swagger-html
            elif '"parameters"' in res.text:
                return 2  # api_docs
            elif '"location"' in res.text:
                return 1  # resource
        except:
            pass
        return 0
    
    def fill_parameters(self, parameters: List[Dict], url: str) -> Tuple[Dict, str]:
        """填充测试数据并替换 URL 中的占位符"""
        filled_params = {}
        path_params = {}
        
        for param in parameters:
            param_name = param.get('name', '')
            param_in = param.get('in', 'query')
            param_type = param.get('type', 'string')
            
            if param_type == 'string':
                value = 'a'
            elif param_type == 'integer':
                value = 1
            elif param_type == 'number':
                value = 1.0
            elif param_type == 'boolean':
                value = True
            elif param_type == 'array':
                value = []
            elif param_type == 'object':
                value = {}
            else:
                value = ''
            
            if param_in == 'query':
                filled_params[param_name] = value
            elif param_in == 'path':
                path_params[param_name] = value
                filled_params[param_name] = value
            elif param_in == 'body':
                if 'body' not in filled_params:
                    filled_params['body'] = {}
                filled_params['body'][param_name] = value
        
        for key, value in path_params.items():
            url = url.replace(f'{{{key}}}', str(value))
        
        return filled_params, url
    
    def resolve_ref(self, ref: str, definitions: Dict) -> Optional[Dict]:
        """解析$ref引用"""
        if not ref:
            return None
        
        ref_name = ref.split('/')[-1]
        return definitions.get(ref_name)
    
    def extract_params_from_schema(self, schema: Dict, definitions: Dict) -> List[Dict]:
        """从schema中提取参数"""
        params = []
        
        if not schema:
            return params
        
        if '$ref' in schema:
            ref_obj = self.resolve_ref(schema['$ref'], definitions)
            if ref_obj:
                props = ref_obj.get('properties', {})
                for prop_name, prop_details in props.items():
                    param_type = prop_details.get('type', 'string')
                    params.append({
                        'name': prop_name,
                        'in': 'body',
                        'type': param_type
                    })
        
        elif schema.get('type') == 'object' and 'properties' in schema:
            for prop_name, prop_details in schema['properties'].items():
                if '$ref' in prop_details:
                    nested_params = self.extract_params_from_schema(prop_details, definitions)
                    params.extend(nested_params)
                else:
                    params.append({
                        'name': prop_name,
                        'in': 'body',
                        'type': prop_details.get('type', 'string')
                    })
        
        return params
    
    def go_api_docs(self, url: str):
        """解析 api-docs 并测试接口"""
        try:
            parsed = urlparse(url)
            domain = f"{parsed.scheme}://{parsed.netloc}"
            
            res = self.http_req(url)
            if not res or res.status_code != 200:
                return
            
            try:
                data = json.loads(res.text)
            except json.JSONDecodeError:
                data_str = res.text.replace("'", '"')
                data_str = re.sub(r'<[^>]*>', lambda match: match.group(0).replace('"', "'"), data_str)
                try:
                    data = json.loads(data_str, strict=False)
                except:
                    return
            
            if 'basePath' in data.keys():
                base_path = data['basePath']
            elif 'servers' in data.keys():
                servers = data['servers']
                if isinstance(servers, list) and servers:
                    base_path = servers[0].get('url', '')
                else:
                    base_path = ''
            else:
                base_path = ''
            
            paths = data.get('paths', {})
            definitions = data.get('definitions', {})
            
            logger.info(f"[*] 解析到 {len(paths)} 个API路径")
            
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() not in ['GET', 'POST']:
                        continue
                    
                    req_path = domain + base_path + path
                    summary = details.get('summary', path)
                    consumes = details.get('consumes', [])
                    params = details.get('parameters', [])
                    
                    param_info = []
                    for param in params:
                        param_name = param.get('name')
                        param_in = param.get('in')
                        schema = param.get('schema')
                        
                        if schema and '$ref' in schema:
                            ref = schema['$ref'].split('/')[-1]
                            if ref in definitions:
                                for prop_name, prop_details in definitions[ref].get('properties', {}).items():
                                    param_info.append({
                                        'name': prop_name,
                                        'in': param_in,
                                        'type': prop_details.get('type')
                                    })
                        elif schema and schema.get('type') == 'array' and '$ref' in schema.get('items', {}):
                            ref = schema['items']['$ref'].split('/')[-1]
                            if ref in definitions:
                                for prop_name, prop_details in definitions[ref].get('properties', {}).items():
                                    param_info.append({
                                        'name': prop_name,
                                        'in': param_in,
                                        'type': prop_details.get('type')
                                    })
                        else:
                            param_type = param.get('type')
                            if param_name:
                                param_info.append({
                                    'name': param_name,
                                    'in': param_in,
                                    'type': param_type
                                })
                    
                    filled_params, new_url = self.fill_parameters(param_info, req_path)
                    headers = {}
                    
                    if 'application/json' in consumes:
                        headers['Content-Type'] = 'application/json'
                    
                    try:
                        logger.info(f"  [*] 测试: {method.upper()} {req_path} | 参数: {filled_params}")
                        
                        if method.lower() == 'get':
                            response = self.http_req(new_url, method='get', params=filled_params)
                            if response:
                                logger.info(f"      → 状态码: {response.status_code}")
                                if response.status_code not in self.black_list_status:
                                    self.findings.append({
                                        'url': new_url,
                                        'method': method.upper(),
                                        'summary': summary,
                                        'status_code': response.status_code,
                                        'response': response.text[:500] if response.text else '',
                                        'params': filled_params
                                    })
                        
                        elif method.lower() == 'post':
                            if 'body' in filled_params:
                                response = self.http_req(new_url, method='post', json=filled_params.get('body'), headers=headers)
                            else:
                                response = self.http_req(new_url, method='post', params=filled_params, headers=headers)
                            
                            if response:
                                logger.info(f"      → 状态码: {response.status_code}")
                                if response.status_code not in self.black_list_status:
                                    self.findings.append({
                                        'url': new_url,
                                        'method': method.upper(),
                                        'summary': summary,
                                        'status_code': response.status_code,
                                        'response': response.text[:500] if response.text else '',
                                        'params': filled_params
                                    })
                    except Exception as e:
                        logger.debug(f"请求接口失败 {method} {new_url}: {e}")
        
        except Exception as e:
            logger.debug(f"解析API文档失败 {url}: {e}")
    
    def go_swagger_html(self, url: str):
        """解析 swagger-ui.html 获取 api 接口路径"""
        try:
            response = self.http_req(url)
            if not response:
                return
            
            html_content = response.text
            
            # 方法1: 从 swagger-initializer.js 中获取
            initializer_pattern = r'<script\s+src=["\']([^"\']*swagger-initializer\.js[^"\']*)["\']'
            initializer_match = re.search(initializer_pattern, html_content)
            
            if initializer_match:
                js_file_path = initializer_match.group(1)
                if js_file_path.startswith('http'):
                    js_file_url = js_file_path
                else:
                    parsed = urlparse(url)
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    base_path = parsed.path.rsplit('/', 1)[0]
                    js_file_url = f"{base_url}{base_path}/{js_file_path.lstrip('/')}"
                
                js_response = self.http_req(js_file_url)
                if js_response:
                    js_content = js_response.text
                    js_pattern = r'const\s+defaultDefinitionUrl\s*=\s*["\']([^"\']+)["\'];'
                    js_match = re.search(js_pattern, js_content)
                    if js_match:
                        api_docs_path = js_match.group(1)
                        if not api_docs_path.startswith('http'):
                            parsed = urlparse(url)
                            base_url = f"{parsed.scheme}://{parsed.netloc}"
                            base_path = parsed.path.rsplit('/', 1)[0]
                            api_docs_path = f"{base_url}{base_path}/{api_docs_path.lstrip('/')}"
                        logger.info(f"[SwaggerHound] 从JS解析到API文档: {api_docs_path}")
                        self.go_api_docs(api_docs_path)
                        return
            
            # 方法2: 从HTML中直接匹配swagger.json或api-docs路径
            logger.info("[SwaggerHound] 尝试从HTML中解析API文档路径...")
            
            # 匹配常见的API文档路径模式
            api_doc_patterns = [
                r'url\s*[=:]\s*["\']([^"\']*(?:swagger\.json|api-docs|openapi\.json)[^"\']*)["\']',
                r'configUrl\s*[=:]\s*["\']([^"\']*)["\']',
                r'"url"\s*:\s*"([^"]*(?:swagger\.json|api-docs|openapi\.json)[^"]*)"',
            ]
            
            for pattern in api_doc_patterns:
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    api_docs_path = match.group(1)
                    if not api_docs_path.startswith('http'):
                        parsed = urlparse(url)
                        base_url = f"{parsed.scheme}://{parsed.netloc}"
                        base_path = parsed.path.rsplit('/', 1)[0]
                        api_docs_path = f"{base_url}{base_path}/{api_docs_path.lstrip('/')}"
                    logger.info(f"[SwaggerHound] 从HTML解析到API文档: {api_docs_path}")
                    self.go_api_docs(api_docs_path)
                    return
            
            # 方法3: 尝试常见的API文档路径
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            base_path = parsed.path.rsplit('/', 1)[0]
            
            common_api_paths = [
                f"{base_url}{base_path}/swagger.json",
                f"{base_url}{base_path}/v1/swagger.json",
                f"{base_url}{base_path}/v2/swagger.json",
                f"{base_url}/swagger/v1/swagger.json",
                f"{base_url}/swagger/v2/swagger.json",
                f"{base_url}/api/swagger.json",
                f"{base_url}/v2/api-docs",
                f"{base_url}/v3/api-docs",
            ]
            
            for api_path in common_api_paths:
                logger.info(f"[SwaggerHound] 尝试探测: {api_path}")
                check_resp = self.http_req(api_path)
                if check_resp and check_resp.status_code == 200:
                    if '"swagger"' in check_resp.text or '"openapi"' in check_resp.text:
                        logger.info(f"[SwaggerHound] 发现API文档: {api_path}")
                        self.go_api_docs(api_path)
                        return
            
            logger.info("[SwaggerHound] 未从Swagger UI解析到API文档")
            
        except Exception as e:
            logger.debug(f"解析Swagger HTML失败 {url}: {e}")
    
    def go_resources(self, url: str):
        """解析 swagger_resources 获取 api-docs"""
        try:
            parsed = urlparse(url)
            domain = f"{parsed.scheme}://{parsed.netloc}"
            
            res = self.http_req(url)
            if not res:
                return
            
            data = json.loads(res.text)
            for item in data:
                location = item.get('location')
                if location:
                    if location.startswith('http'):
                        target = location
                    elif parsed.path.strip('/'):
                        target = url.rsplit('/', 1)[0] + location
                    else:
                        target = domain + location
                    self.go_api_docs(target)
        
        except Exception as e:
            logger.debug(f"解析swagger_resources失败 {url}: {e}")
    
    def discover_and_scan(self, target_url: str) -> List[Dict]:
        """
        自动发现并扫描Swagger API
        
        Args:
            target_url: 目标URL
            
        Returns:
            扫描结果列表
        """
        self.findings = []
        
        # 首先检查传入的URL本身
        url_type = self.check_page(target_url)
        
        if url_type == 1:
            logger.info(f"[SwaggerHound] 发现 swagger-resources: {target_url}")
            self.go_resources(target_url)
            return self.findings
        elif url_type == 2:
            logger.info(f"[SwaggerHound] 发现 API 文档: {target_url}")
            self.go_api_docs(target_url)
            return self.findings
        elif url_type == 3:
            logger.info(f"[SwaggerHound] 发现 Swagger UI: {target_url}")
            self.go_swagger_html(target_url)
            return self.findings
        
        # 如果传入的URL不是Swagger相关页面，尝试常见路径
        common_paths = [
            '/swagger-ui.html',
            '/swagger-ui/index.html',
            '/swagger.json',
            '/api/swagger.json',
            '/v2/api-docs',
            '/v3/api-docs',
            '/api-docs',
            '/swagger-resources',
            '/api/swagger-ui.html',
            '/swagger',
        ]
        
        parsed = urlparse(target_url)
        domain = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in common_paths:
            test_url = domain + path
            url_type = self.check_page(test_url)
            
            if url_type == 1:
                logger.info(f"[SwaggerHound] 发现 swagger-resources: {test_url}")
                self.go_resources(test_url)
                break
            elif url_type == 2:
                logger.info(f"[SwaggerHound] 发现 API 文档: {test_url}")
                self.go_api_docs(test_url)
                break
            elif url_type == 3:
                logger.info(f"[SwaggerHound] 发现 Swagger UI: {test_url}")
                self.go_swagger_html(test_url)
                break
        
        return self.findings


def scan_swagger_api(session, target_url: str, proxies: dict = None) -> List[Dict]:
    """
    便捷函数：扫描目标URL的Swagger API
    
    Args:
        session: requests session对象
        target_url: 目标URL
        proxies: 代理设置
        
    Returns:
        扫描结果列表
    """
    hound = SwaggerHound(session, proxies)
    return hound.discover_and_scan(target_url)
