#!/usr/bin/env python3
"""
API文档解析模块 v1.0
支持解析Swagger/OpenAPI、Postman Collection、WADL等格式的API文档
"""

import re
import json
import yaml
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


@dataclass
class APIEndpoint:
    """API端点信息"""
    path: str
    method: str
    summary: str = ""
    description: str = ""
    parameters: List[Dict] = field(default_factory=list)
    request_body: Dict = field(default_factory=dict)
    responses: Dict = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    auth_required: bool = False
    source_doc: str = ""


@dataclass
class ParsedAPIDoc:
    """解析后的API文档"""
    title: str
    version: str
    description: str = ""
    base_url: str = ""
    endpoints: List[APIEndpoint] = field(default_factory=list)
    auth_schemes: List[Dict] = field(default_factory=list)
    doc_type: str = ""  # swagger, openapi, postman, wadl


class SwaggerParser:
    """Swagger/OpenAPI文档解析器"""
    
    COMMON_PATHS = [
        "/swagger-ui.html",
        "/swagger-ui/index.html",
        "/swagger.json",
        "/swagger.yaml",
        "/swagger.yml",
        "/api/swagger.json",
        "/api/swagger.yaml",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api-docs",
        "/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/api/openapi.json",
        "/api/v1/docs",
        "/api/v2/docs",
        "/docs",
        "/api/documentation",
        "/api/swagger-ui.html",
        "/swagger",
        "/api/swagger",
        "/swagger/v1/swagger.json",
        "/swagger/v2/swagger.json",
    ]
    
    def __init__(self, session):
        self.session = session
    
    def discover(self, base_url: str) -> Optional[str]:
        """
        自动发现API文档地址
        
        Args:
            base_url: 基础URL
            
        Returns:
            发现的API文档URL或None
        """
        for path in self.COMMON_PATHS:
            doc_url = urljoin(base_url, path)
            try:
                # 使用(连接超时, 读取超时)元组格式
                resp = self.session.get(doc_url, timeout=(3, 10))
                if resp.status_code == 200:
                    content_type = resp.headers.get('Content-Type', '')
                    if 'json' in content_type or 'yaml' in content_type or \
                       'swagger' in resp.text[:500].lower() or \
                       'openapi' in resp.text[:500].lower():
                        logger.info(f"[+] 发现API文档: {doc_url}")
                        return doc_url
            except Exception as e:
                logger.debug(f"API doc discovery error for {doc_url}: {e}")
        
        return None
    
    def parse(self, doc_url: str, content: str = None) -> Optional[ParsedAPIDoc]:
        """
        解析Swagger/OpenAPI文档
        
        Args:
            doc_url: API文档URL
            content: 文档内容（可选，如果不提供则自动获取）
            
        Returns:
            解析后的API文档对象
        """
        try:
            if content is None:
                resp = self.session.get(doc_url, timeout=(3, 15))
                content = resp.text
            
            # 解析JSON或YAML
            if doc_url.endswith('.yaml') or doc_url.endswith('.yml'):
                doc_data = yaml.safe_load(content)
            else:
                try:
                    doc_data = json.loads(content)
                except json.JSONDecodeError:
                    # 尝试YAML解析
                    doc_data = yaml.safe_load(content)
            
            if not doc_data:
                return None
            
            # 判断文档类型和版本
            swagger_version = doc_data.get('swagger', '')
            openapi_version = doc_data.get('openapi', '')
            
            if swagger_version.startswith('2'):
                return self._parse_swagger_v2(doc_data, doc_url)
            elif openapi_version.startswith('3'):
                return self._parse_openapi_v3(doc_data, doc_url)
            elif 'swagger' in str(doc_data).lower():
                return self._parse_swagger_v2(doc_data, doc_url)
            else:
                logger.warning(f"未知的API文档格式: {doc_url}")
                return None
                
        except Exception as e:
            logger.error(f"解析API文档失败 {doc_url}: {e}")
            return None
    
    def _parse_swagger_v2(self, doc_data: Dict, doc_url: str) -> ParsedAPIDoc:
        """解析Swagger 2.0文档"""
        parsed = ParsedAPIDoc(
            title=doc_data.get('info', {}).get('title', 'Unknown API'),
            version=doc_data.get('info', {}).get('version', '1.0'),
            description=doc_data.get('info', {}).get('description', ''),
            base_url=self._resolve_base_url_v2(doc_data, doc_url),
            doc_type='swagger-v2'
        )
        
        # 解析安全方案
        if 'securityDefinitions' in doc_data:
            parsed.auth_schemes = list(doc_data['securityDefinitions'].values())
        
        # 解析路径
        paths = doc_data.get('paths', {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            
            for method, operation in methods.items():
                if method.startswith('x-') or not isinstance(operation, dict):
                    continue
                
                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    summary=operation.get('summary', ''),
                    description=operation.get('description', ''),
                    parameters=operation.get('parameters', []),
                    responses=operation.get('responses', {}),
                    tags=operation.get('tags', []),
                    auth_required='security' in operation or bool(doc_data.get('security', [])),
                    source_doc=doc_url
                )
                
                # 处理请求体
                if 'consumes' in operation:
                    endpoint.request_body['content_type'] = operation['consumes']
                
                parsed.endpoints.append(endpoint)
        
        return parsed
    
    def _parse_openapi_v3(self, doc_data: Dict, doc_url: str) -> ParsedAPIDoc:
        """解析OpenAPI 3.0文档"""
        parsed = ParsedAPIDoc(
            title=doc_data.get('info', {}).get('title', 'Unknown API'),
            version=doc_data.get('info', {}).get('version', '1.0'),
            description=doc_data.get('info', {}).get('description', ''),
            base_url=self._resolve_base_url_v3(doc_data, doc_url),
            doc_type='openapi-v3'
        )
        
        # 解析安全方案
        if 'components' in doc_data and 'securitySchemes' in doc_data['components']:
            parsed.auth_schemes = list(doc_data['components']['securitySchemes'].values())
        
        # 解析路径
        paths = doc_data.get('paths', {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            
            for method, operation in methods.items():
                if method.startswith('x-') or not isinstance(operation, dict):
                    continue
                
                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    summary=operation.get('summary', ''),
                    description=operation.get('description', ''),
                    responses=operation.get('responses', {}),
                    tags=operation.get('tags', []),
                    auth_required='security' in operation or bool(doc_data.get('security', [])),
                    source_doc=doc_url
                )
                
                # 解析参数
                if 'parameters' in operation:
                    endpoint.parameters = operation['parameters']
                
                # 解析请求体
                if 'requestBody' in operation:
                    endpoint.request_body = operation['requestBody']
                
                parsed.endpoints.append(endpoint)
        
        return parsed
    
    def _resolve_base_url_v2(self, doc_data: Dict, doc_url: str) -> str:
        """解析Swagger 2.0的基础URL"""
        parsed = urlparse(doc_url)
        
        # 从文档中获取host和basePath
        host = doc_data.get('host', parsed.netloc)
        base_path = doc_data.get('basePath', '')
        schemes = doc_data.get('schemes', ['https'])
        
        scheme = schemes[0] if schemes else 'https'
        return f"{scheme}://{host}{base_path}"
    
    def _resolve_base_url_v3(self, doc_data: Dict, doc_url: str) -> str:
        """解析OpenAPI 3.0的基础URL"""
        servers = doc_data.get('servers', [])
        if servers:
            return servers[0].get('url', '')
        
        parsed = urlparse(doc_url)
        return f"{parsed.scheme}://{parsed.netloc}"


class PostmanParser:
    """Postman Collection解析器"""
    
    COMMON_PATHS = [
        "/postman/collection.json",
        "/api/postman",
        "/postman",
        "/collection.json",
    ]
    
    def __init__(self, session):
        self.session = session
    
    def discover(self, base_url: str) -> Optional[str]:
        """发现Postman Collection"""
        for path in self.COMMON_PATHS:
            doc_url = urljoin(base_url, path)
            try:
                resp = self.session.get(doc_url, timeout=(3, 10))
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if 'info' in data or 'item' in data:
                            return doc_url
                    except:
                        pass
            except Exception as e:
                logger.debug(f"Postman discovery error: {e}")
        
        return None
    
    def parse(self, doc_url: str, content: str = None) -> Optional[ParsedAPIDoc]:
        """解析Postman Collection"""
        try:
            if content is None:
                resp = self.session.get(doc_url, timeout=(3, 15))
                data = resp.json()
            else:
                data = json.loads(content)
            
            info = data.get('info', {})
            parsed = ParsedAPIDoc(
                title=info.get('name', 'Postman Collection'),
                version=info.get('version', '1.0'),
                description=info.get('description', ''),
                base_url="",
                doc_type='postman'
            )
            
            # 递归解析items
            items = data.get('item', [])
            self._parse_postman_items(items, parsed, doc_url)
            
            return parsed
            
        except Exception as e:
            logger.error(f"解析Postman Collection失败: {e}")
            return None
    
    def _parse_postman_items(self, items: List[Dict], parsed: ParsedAPIDoc, source: str, parent_path: str = ""):
        """递归解析Postman items"""
        for item in items:
            if 'item' in item:
                # 这是一个文件夹
                folder_name = item.get('name', '')
                self._parse_postman_items(item['item'], parsed, source, f"{parent_path}/{folder_name}")
            else:
                # 这是一个请求
                request = item.get('request', {})
                if isinstance(request, str):
                    continue
                
                url_data = request.get('url', {})
                if isinstance(url_data, str):
                    path = url_data
                else:
                    path = "/" + "/".join(url_data.get('path', []))
                
                method = request.get('method', 'GET')
                
                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    summary=item.get('name', ''),
                    description=request.get('description', ''),
                    parameters=[],
                    source_doc=source
                )
                
                # 解析参数
                if isinstance(url_data, dict):
                    for param in url_data.get('query', []):
                        endpoint.parameters.append({
                            'name': param.get('key', ''),
                            'in': 'query',
                            'type': 'string'
                        })
                
                # 解析请求体
                if 'body' in request:
                    endpoint.request_body = request['body']
                
                parsed.endpoints.append(endpoint)


class WADLParser:
    """WADL (Web Application Description Language)解析器"""
    
    COMMON_PATHS = [
        "/application.wadl",
        "/api/application.wadl",
        "/wadl",
        "/api/wadl",
    ]
    
    def __init__(self, session):
        self.session = session
    
    def discover(self, base_url: str) -> Optional[str]:
        """发现WADL文档"""
        for path in self.COMMON_PATHS:
            doc_url = urljoin(base_url, path)
            try:
                resp = self.session.get(doc_url, timeout=(3, 10))
                if resp.status_code == 200 and 'application.wadl' in resp.text:
                    return doc_url
            except Exception as e:
                logger.debug(f"WADL discovery error: {e}")
        
        return None
    
    def parse(self, doc_url: str, content: str = None) -> Optional[ParsedAPIDoc]:
        """解析WADL文档"""
        try:
            import xml.etree.ElementTree as ET
            
            if content is None:
                resp = self.session.get(doc_url, timeout=(3, 15))
                content = resp.text
            
            root = ET.fromstring(content)
            
            # 定义命名空间
            ns = {'wadl': 'http://wadl.dev.java.net/2009/02'}
            
            parsed = ParsedAPIDoc(
                title="WADL API",
                version="1.0",
                base_url="",
                doc_type='wadl'
            )
            
            # 解析资源
            resources = root.find('.//wadl:resources', ns)
            if resources is not None:
                base = resources.get('base', '')
                parsed.base_url = base
                
                for resource in resources.findall('.//wadl:resource', ns):
                    path = resource.get('path', '')
                    
                    for method in resource.findall('.//wadl:method', ns):
                        method_name = method.get('name', 'GET')
                        
                        endpoint = APIEndpoint(
                            path=path,
                            method=method_name.upper(),
                            summary=method.get('id', ''),
                            source_doc=doc_url
                        )
                        
                        # 解析参数
                        for param in method.findall('.//wadl:param', ns):
                            endpoint.parameters.append({
                                'name': param.get('name', ''),
                                'in': param.get('style', 'query'),
                                'type': param.get('type', 'string')
                            })
                        
                        parsed.endpoints.append(endpoint)
            
            return parsed
            
        except Exception as e:
            logger.error(f"解析WADL失败: {e}")
            return None


class APIDocParser:
    """API文档解析器主类"""
    
    def __init__(self, session):
        self.session = session
        self.swagger_parser = SwaggerParser(session)
        self.postman_parser = PostmanParser(session)
        self.wadl_parser = WADLParser(session)
        self.parsed_docs: List[ParsedAPIDoc] = []
    
    def discover_and_parse(self, base_url: str, max_total_time: int = 30) -> List[ParsedAPIDoc]:
        """
        自动发现并解析所有类型的API文档
        
        Args:
            base_url: 目标基础URL
            max_total_time: 最大总超时时间（秒），默认30秒
            
        Returns:
            解析后的API文档列表
        """
        import time
        start_time = time.time()
        self.parsed_docs = []
        
        # 尝试发现Swagger/OpenAPI
        swagger_url = self.swagger_parser.discover(base_url)
        if swagger_url:
            doc = self.swagger_parser.parse(swagger_url)
            if doc:
                self.parsed_docs.append(doc)
                logger.info(f"[+] 解析Swagger/OpenAPI文档: {len(doc.endpoints)} 个端点")
        
        # 检查超时
        if time.time() - start_time > max_total_time:
            logger.warning(f"[!] API文档搜索超时（>{max_total_time}秒），停止搜索")
            return self.parsed_docs
        
        # 尝试发现Postman
        postman_url = self.postman_parser.discover(base_url)
        if postman_url:
            doc = self.postman_parser.parse(postman_url)
            if doc:
                self.parsed_docs.append(doc)
                logger.info(f"[+] 解析Postman Collection: {len(doc.endpoints)} 个端点")
        
        # 检查超时
        if time.time() - start_time > max_total_time:
            logger.warning(f"[!] API文档搜索超时（>{max_total_time}秒），停止搜索")
            return self.parsed_docs
        
        # 尝试发现WADL
        wadl_url = self.wadl_parser.discover(base_url)
        if wadl_url:
            doc = self.wadl_parser.parse(wadl_url)
            if doc:
                self.parsed_docs.append(doc)
                logger.info(f"[+] 解析WADL文档: {len(doc.endpoints)} 个端点")
        
        return self.parsed_docs
    
    def get_all_endpoints(self) -> List[APIEndpoint]:
        """获取所有解析的端点"""
        all_endpoints = []
        for doc in self.parsed_docs:
            all_endpoints.extend(doc.endpoints)
        return all_endpoints
    
    def get_endpoints_by_tag(self, tag: str) -> List[APIEndpoint]:
        """按标签获取端点"""
        endpoints = []
        for doc in self.parsed_docs:
            for ep in doc.endpoints:
                if tag in ep.tags:
                    endpoints.append(ep)
        return endpoints
    
    def get_summary(self) -> Dict[str, Any]:
        """获取解析摘要"""
        summary = {
            'total_docs': len(self.parsed_docs),
            'total_endpoints': sum(len(doc.endpoints) for doc in self.parsed_docs),
            'docs': []
        }
        
        for doc in self.parsed_docs:
            summary['docs'].append({
                'title': doc.title,
                'version': doc.version,
                'type': doc.doc_type,
                'endpoint_count': len(doc.endpoints)
            })
        
        return summary


def parse_api_docs(session, base_url: str) -> List[ParsedAPIDoc]:
    """
    便捷的API文档解析函数
    
    Args:
        session: requests会话
        base_url: 目标基础URL
        
    Returns:
        解析后的API文档列表
    """
    parser = APIDocParser(session)
    return parser.discover_and_parse(base_url)


# 导出
__all__ = [
    'APIDocParser', 'SwaggerParser', 'PostmanParser', 'WADLParser',
    'APIEndpoint', 'ParsedAPIDoc', 'parse_api_docs'
]
