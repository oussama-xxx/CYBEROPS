import hashlib
import re
import requests
import xml.etree.ElementTree as ET
from html import unescape
from concurrent.futures import ThreadPoolExecutor
import subprocess
import time
import json
import os
import struct
from collections import Counter
from datetime import datetime
from django.conf import settings
import google.generativeai as genai

# 🔑 CRYPTO & THREAT INTEL TOKENS INTEGRATION
SHODAN_API_KEY = "??"
VIRUSTOTAL_API_KEY = "??"
ABUSEIPDB_API_KEY = "??"
GEMINI_API_KEY = "??"



genai.configure(api_key=GEMINI_API_KEY)

def askgemini(message):
    model = genai.GenerativeModel('gemini-2.5-flash')
    response = model.generate_content(message)
    return response.text.strip()

# =====================================================================
# 🖥️ ZABBIX INTEGRATION CONFIGURATION
# =====================================================================
ZABBIX_URL = "http://localhost:8080/api_jsonrpc.php"
ZABBIX_AUTH_TOKEN = "4b214b54f400424b1785ee709162224a"  # Token mis à jour


class ZabbixService:
    """Service pour interagir avec l'API Zabbix - Surveillance d'infrastructure"""
    
    @classmethod
    def _make_request(cls, method, params, auth_required=True):
        """Faire une requête à l'API Zabbix"""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }
        
        if auth_required and ZABBIX_AUTH_TOKEN:
            payload["auth"] = ZABBIX_AUTH_TOKEN
        
        try:
            response = requests.post(
                ZABBIX_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if "error" in data:
                    print(f"Zabbix API Error: {data['error']}")
                    return None
                return data.get("result", [])
            else:
                print(f"HTTP Error: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"Connection Error: {e}")
            return None
    
    @classmethod
    def get_hosts(cls, limit=None):
        """Récupérer tous les hôtes surveillés"""
        params = {
            "output": ["hostid", "host", "name", "status", "available", "error"],
            "selectInterfaces": ["ip", "port", "type", "main"],
            "selectGroups": ["name"]
        }
        
        result = cls._make_request("host.get", params)
        
        if result and limit:
            result = result[:limit]
        
        return result
    
    @classmethod
    def get_problems(cls, severities=None, limit=50, recent=True):
        """Récupérer les problèmes actifs"""
        params = {
            "output": ["eventid", "name", "severity", "clock", "acknowledged"],
            "sortfield": ["eventid"],
            "sortorder": "DESC",
            "limit": limit
        }
        
        if severities:
            params["severities"] = severities
        
        if recent:
            params["recent"] = "true"
        
        result = cls._make_request("problem.get", params)
        
        # Formater les dates
        if result:
            for problem in result:
                if 'clock' in problem:
                    try:
                        problem['clock_formatted'] = datetime.fromtimestamp(
                            int(problem['clock'])
                        ).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        problem['clock_formatted'] = problem['clock']
        
        return result
    
    @classmethod
    def get_triggers(cls, host_id=None, min_severity=None, only_problems=True):
        """Récupérer les triggers des hôtes"""
        params = {
            "output": ["triggerid", "description", "priority", "status", "value", "lastchange"],
            "selectHosts": ["hostid", "name"],
            "monitored": True
        }
        
        if only_problems:
            params["only_true"] = True
            params["filter"] = {"value": 1}
        
        if host_id:
            params["hostids"] = host_id
        
        if min_severity is not None:
            params["min_severity"] = min_severity
        
        result = cls._make_request("trigger.get", params)
        
        if result:
            for trigger in result:
                if 'lastchange' in trigger:
                    try:
                        trigger['lastchange_formatted'] = datetime.fromtimestamp(
                            int(trigger['lastchange'])
                        ).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        trigger['lastchange_formatted'] = trigger['lastchange']
        
        return result
    
    @classmethod
    def get_dashboard_data(cls):
        """Récupérer toutes les données pour le tableau de bord"""
        hosts = cls.get_hosts()
        problems = cls.get_problems(limit=30)
        
        # Statistiques des hôtes
        total_hosts = len(hosts) if hosts else 0
        available_hosts = 0
        unavailable_hosts = 0
        unknown_hosts = 0
        
        if hosts:
            for host in hosts:
                available = host.get('available', '0')
                if available == '1' or available == 1:
                    available_hosts += 1
                elif available == '2' or available == 2:
                    unavailable_hosts += 1
                else:
                    unknown_hosts += 1
        
        # Statistiques des problèmes par sévérité
        severity_stats = {
            'not_classified': 0,   # 0
            'information': 0,       # 1
            'warning': 0,           # 2
            'average': 0,           # 3
            'high': 0,              # 4
            'disaster': 0           # 5
        }
        
        if problems:
            for problem in problems:
                severity = problem.get('severity', 0)
                if severity == 0 or severity == '0':
                    severity_stats['not_classified'] += 1
                elif severity == 1 or severity == '1':
                    severity_stats['information'] += 1
                elif severity == 2 or severity == '2':
                    severity_stats['warning'] += 1
                elif severity == 3 or severity == '3':
                    severity_stats['average'] += 1
                elif severity == 4 or severity == '4':
                    severity_stats['high'] += 1
                elif severity == 5 or severity == '5':
                    severity_stats['disaster'] += 1
        
        return {
            'total_hosts': total_hosts,
            'available_hosts': available_hosts,
            'unavailable_hosts': unavailable_hosts,
            'unknown_hosts': unknown_hosts,
            'total_problems': len(problems) if problems else 0,
            'severity_stats': severity_stats,
            'hosts': hosts[:20] if hosts else [],
            'problems': problems[:20] if problems else []
        }
    
    # =====================================================================
    # 🗺️ ZABBIX MAPS METHODS
    # =====================================================================
    
    @classmethod
    def get_maps(cls):
        """Récupérer toutes les maps Zabbix"""
        params = {
            "output": ["sysmapid", "name", "width", "height", "backgroundid", "label_type", "label_location"],
            "selectSelements": ["selementid", "elementid", "elementtype", "label", "x", "y", "iconid_off", "iconid_on", "urls"],
            "selectLinks": ["linkid", "label", "selementid1", "selementid2", "color", "drawtype", "linktriggers"]
        }
        return cls._make_request("map.get", params)
    
    @classmethod
    def get_map_by_id(cls, map_id):
        """Récupérer une map spécifique avec tous ses éléments"""
        params = {
            "output": "extend",
            "sysmapids": map_id,
            "selectSelements": [
                "selementid", "elementid", "elementtype", "label", "x", "y", 
                "iconid_off", "iconid_on", "iconid_disabled", "urls", "application"
            ],
            "selectLinks": [
                "linkid", "label", "selementid1", "selementid2", 
                "color", "drawtype", "linktriggers"
            ],
            "selectShapes": "extend",
            "expandUrls": "extend"
        }
        result = cls._make_request("map.get", params)
        return result[0] if result else None
    
    @classmethod
    def get_map_elements_status(cls, map_data):
        """Récupérer l'état des éléments d'une map"""
        if not map_data:
            return None
        
        elements = map_data.get('selements', [])
        
        # Filtrer les éléments de type hôte (elementtype = 0)
        host_elements = [e for e in elements if e.get('elementtype') == 0]
        
        if not host_elements:
            map_data['selements'] = elements
            return map_data
        
        # Récupérer les IDs des hôtes
        host_ids = [e['elementid'] for e in host_elements if e.get('elementid')]
        
        if not host_ids:
            map_data['selements'] = elements
            return map_data
        
        # Récupérer le statut des hôtes
        hosts_params = {
            "output": ["hostid", "name", "status", "available"],
            "hostids": host_ids,
            "selectTriggers": ["triggerid", "description", "priority", "value", "lastchange"]
        }
        hosts = cls._make_request("host.get", hosts_params)
        
        # Créer un mapping du statut des hôtes
        host_status = {}
        if hosts:
            for host in hosts:
                host_id = host.get('hostid')
                triggers = host.get('triggers', [])
                problem_count = sum(1 for t in triggers if t.get('value') == '1')
                max_severity = 0
                for t in triggers:
                    if t.get('value') == '1':
                        severity = int(t.get('priority', 0))
                        if severity > max_severity:
                            max_severity = severity
                
                host_status[host_id] = {
                    'available': host.get('available'),
                    'status': host.get('status'),
                    'problem_count': problem_count,
                    'max_severity': max_severity,
                    'name': host.get('name')
                }
        
        # Mettre à jour les éléments avec leur statut
        for element in elements:
            element_id = element.get('elementid')
            if element_id in host_status:
                element['status'] = host_status[element_id]
                
                # Ajouter une classe CSS basée sur la sévérité
                severity = host_status[element_id]['max_severity']
                if severity >= 4:
                    element['status_class'] = 'element-critical'
                    element['status_icon'] = '🔴'
                    element['status_text'] = 'CRITICAL'
                elif severity == 3:
                    element['status_class'] = 'element-high'
                    element['status_icon'] = '🟠'
                    element['status_text'] = 'HIGH'
                elif severity == 2:
                    element['status_class'] = 'element-average'
                    element['status_icon'] = '🟡'
                    element['status_text'] = 'AVERAGE'
                elif severity == 1:
                    element['status_class'] = 'element-warning'
                    element['status_icon'] = '🔵'
                    element['status_text'] = 'WARNING'
                elif host_status[element_id]['available'] == '2':
                    element['status_class'] = 'element-unavailable'
                    element['status_icon'] = '⚫'
                    element['status_text'] = 'UNAVAILABLE'
                elif host_status[element_id]['problem_count'] > 0:
                    element['status_class'] = 'element-problem'
                    element['status_icon'] = '⚠️'
                    element['status_text'] = 'PROBLEM'
                else:
                    element['status_class'] = 'element-ok'
                    element['status_icon'] = '🟢'
                    element['status_text'] = 'OK'
            else:
                element['status_class'] = 'element-unknown'
                element['status_icon'] = '❓'
                element['status_text'] = 'UNKNOWN'
        
        map_data['selements'] = elements
        return map_data
    
    @classmethod
    def get_all_maps_with_status(cls):
        """Récupérer toutes les maps Zabbix avec leurs statuts"""
        maps = cls.get_maps()
        if not maps:
            print("[Zabbix] No maps found")
            return []
        
        result = []
        for map_item in maps:
            map_id = map_item.get('sysmapid')
            map_name = map_item.get('name', 'Unknown')
            print(f"[Zabbix] Processing map: {map_name} (ID: {map_id})")
            
            # Récupérer la map complète
            full_map = cls.get_map_by_id(map_id)
            if full_map:
                # Ajouter les dimensions
                if 'width' not in full_map:
                    full_map['width'] = map_item.get('width', 800)
                if 'height' not in full_map:
                    full_map['height'] = map_item.get('height', 600)
                
                # Récupérer le statut des éléments
                map_with_status = cls.get_map_elements_status(full_map)
                if map_with_status:
                    result.append(map_with_status)
                    print(f"[Zabbix] Map '{map_name}' loaded with {len(map_with_status.get('selements', []))} elements")
        
        print(f"[Zabbix] Total maps loaded: {len(result)}")
        return result
    
    @classmethod
    def get_map_by_name(cls, map_name):
        """Récupérer une map par son nom"""
        maps = cls.get_maps()
        if not maps:
            return None
        
        for map_item in maps:
            if map_item.get('name', '').lower() == map_name.lower():
                return cls.get_map_by_id(map_item.get('sysmapid'))
        return None
    
    @classmethod
    def get_cyberops_map(cls):
        """Récupérer spécifiquement la map CYBEROPS ARCHITECTURE"""
        return cls.get_map_by_name("CYBEROPS ARCHITECTURE")
    
    @classmethod
    def get_host_triggers_status(cls, host_id):
        """Récupérer les triggers d'un hôte spécifique avec leurs statuts"""
        params = {
            "output": ["triggerid", "description", "priority", "status", "value", "lastchange", "comments"],
            "hostids": host_id,
            "only_true": True,
            "monitored": True,
            "selectHosts": ["hostid", "name"]
        }
        result = cls._make_request("trigger.get", params)
        
        if result:
            for trigger in result:
                if 'lastchange' in trigger:
                    try:
                        trigger['lastchange_formatted'] = datetime.fromtimestamp(
                            int(trigger['lastchange'])
                        ).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        trigger['lastchange_formatted'] = trigger['lastchange']
        
        return result


class OSINTService:

    @staticmethod
    def analyze_ip(ip_address):
        """Initialisation dyal l-Matrix blueprint (IP Intelligence)"""
        intel_result = {
            "ip": ip_address,
            "risk_score": 0,
            "status": "CLEAN // SECURE",
            "country": "Unknown Node",
            "city": "Unknown",
            "provider": "Unknown Infrastructure",
            "organization": "N/A",
            "open_ports": "None Detected",
            "os": "N/A",
            "vulns": "None Detected",
            "abuse_reports": 0,
            "blacklist_status": "CLEAN",
            "vt_positives": 0,
            "vt_total": 0
        }

        # 🛰️ REQUÊTE SHODAN
        try:
            shodan_url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
            shodan_resp = requests.get(shodan_url, timeout=6)
            if shodan_resp.status_code == 200:
                s_data = shodan_resp.json()
                intel_result["country"] = s_data.get("country_name", "Unknown Node")
                intel_result["city"] = s_data.get("city", "Unknown")
                intel_result["provider"] = s_data.get("isp", "Unknown Infrastructure")
                intel_result["organization"] = s_data.get("org", "N/A")
                intel_result["os"] = s_data.get("os", "N/A")
                
                ports = s_data.get("ports", [])
                if ports:
                    intel_result["open_ports"] = ", ".join(map(str, ports))
                
                vulns = s_data.get("vulns", [])
                if vulns:
                    intel_result["vulns"] = ", ".join(vulns[:4])
        except Exception:
            pass

        # 🔏 REQUÊTE ABUSEIPDB
        try:
            abuse_url = "https://api.abuseipdb.com/api/v2/check"
            headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
            params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
            abuse_resp = requests.get(abuse_url, headers=headers, params=params, timeout=5)
            
            if abuse_resp.status_code == 200:
                a_data = abuse_resp.json().get('data', {})
                score = a_data.get('abuseConfidenceScore', 0)
                intel_result["risk_score"] = score
                intel_result["abuse_reports"] = a_data.get('totalReports', 0)
                
                if score > 50:
                    intel_result["status"] = "CRITICAL // MALICIOUS_ALERT"
                    intel_result["blacklist_status"] = "FLAGGED // HIGH_RISK"
                elif score > 15:
                    intel_result["status"] = "WARNING // SUSPICIOUS_ACTIVITY"
                    intel_result["blacklist_status"] = "SUSPICIOUS_LEDGER"
        except Exception:
            pass

        # ☣️ REQUÊTE VIRUSTOTAL v3 (IP)
        try:
            vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {'x-apikey': VIRUSTOTAL_API_KEY}
            vt_resp = requests.get(vt_url, headers=headers, timeout=6)
            
            if vt_resp.status_code == 200:
                vt_data = vt_resp.json().get('data', {})
                stats = vt_data.get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total = malicious + stats.get('harmless', 0) + stats.get('suspicious', 0) + stats.get('undetected', 0)
                
                intel_result["vt_positives"] = malicious
                intel_result["vt_total"] = total
                if malicious > 0:
                    intel_result["status"] = "ALERT // VT_THREAT_DETECTED"
        except Exception:
            pass

        return intel_result

    @staticmethod
    def analyze_url(url_target):
        """Analyse en temps réel des URLs / Domaines via VirusTotal API v3"""
        import base64
        url_id = base64.urlsafe_b64encode(url_target.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        
        intel_result = {
            "risk_score": 0,
            "vt_positives": 0,
            "vt_total": 0,
            "gsb_flagged": False,
            "phish_flagged": False,
            "domain_age": "N/A",
            "registrar": "Unknown Registrar",
            "ssl_valid": True,
            "ssl_issuer": "Domain Control Validated"
        }

        try:
            resp = requests.get(url, headers=headers, timeout=6)
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                attributes = data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                intel_result["vt_positives"] = malicious
                intel_result["vt_total"] = total if total > 0 else 94
                if total > 0:
                    intel_result["risk_score"] = int((malicious / total) * 100)
                
                if malicious > 0: 
                    intel_result["gsb_flagged"] = True
                if malicious > 3: 
                    intel_result["phish_flagged"] = True
                    
                categories = attributes.get('categories', {})
                if categories:
                    intel_result["registrar"] = next(iter(categories.values()))
        except Exception:
            pass

        return intel_result

    @staticmethod
    def analyze_file(file_obj):
        """Analyse d'un fichier réel via VirusTotal API v3 (SHA256 + Sync Live)"""
        if not file_obj: return {}

        sha256_hash = hashlib.sha256()
        for chunk in file_obj.chunks():
            sha256_hash.update(chunk)
        file_hash = sha256_hash.hexdigest()

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}

        try:
            resp = requests.get(url, headers=headers, timeout=7)
            if resp.status_code == 200:
                vt_data = resp.json().get('data', {})
                attributes = vt_data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                if total == 0: total = 74

                if malicious > 3:
                    verdict = "danger"
                    risk_score = int((malicious / total) * 100)
                elif malicious > 0 or suspicious > 1:
                    verdict = "suspicious"
                    risk_score = 45
                else:
                    verdict = "clean"
                    risk_score = 0

                return {
                    "file_name": file_obj.name, 
                    "file_size": f"{round(file_obj.size / 1024, 2)} KB",
                    "sha256": file_hash, 
                    "verdict": verdict, 
                    "risk_score": risk_score,
                    "malicious_count": malicious, 
                    "suspicious_count": suspicious,
                    "clean_count": harmless + undetected, 
                    "total_engines": total,
                    "file_type": attributes.get('type_description', 'Generic Binary'),
                    "magic_bytes": attributes.get('magic', 'N/A'), 
                    "first_seen": attributes.get('first_submission_date', 'N/A')
                }
            elif resp.status_code == 404:
                return {
                    "file_name": file_obj.name, 
                    "file_size": f"{round(file_obj.size / 1024, 2)} KB",
                    "sha256": file_hash, 
                    "verdict": "clean", 
                    "risk_score": 0, 
                    "malicious_count": 0,
                    "suspicious_count": 0, 
                    "clean_count": 0, 
                    "total_engines": 0, 
                    "file_type": "New / Unseen File",
                    "magic_bytes": "No matching malicious signature found in global databases.", 
                    "first_seen": "Just Now"
                }
        except Exception:
            pass

        return {
            "file_name": file_obj.name, 
            "file_size": f"{round(file_obj.size / 1024, 2)} KB", 
            "sha256": file_hash, 
            "verdict": "clean", 
            "risk_score": 0
        }

    @staticmethod
    def check_blacklist(ip_address):
        """Système hybride tactique : Vérification de la BD locale + Live API AbuseIPDB v2"""
        from .models import BlacklistedIP 
        result = {
            "target": ip_address, 
            "source": "GLOBAL_THREAT_FEED", 
            "verdict": "clean", 
            "risk_score": 0,
            "reason": "Passed all active firewall ledger checks.", 
            "total_reports": 0, 
            "country_code": "N/A"
        }

        local_ban = BlacklistedIP.objects.filter(ip_address=ip_address).first()
        if local_ban:
            result.update({
                "source": "LOCAL_FIREWALL_DATABASE", 
                "verdict": "danger", 
                "risk_score": 100,
                "reason": f"CRITICAL ACCÈS BLOCKED: {local_ban.reason}"
            })
            return result

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
        params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}

        try:
            resp = requests.get(url, headers=headers, params=params, timeout=5)
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                result["risk_score"] = score
                result["total_reports"] = data.get('totalReports', 0)
                result["country_code"] = data.get('countryCode', 'N/A')

                if score > 50:
                    result["verdict"] = "danger"
                    result["reason"] = f"Malicious activity flagged by global ledger. Threat confidence at {score}%."
                elif score > 15:
                    result["verdict"] = "suspicious"
                
                if score >= 85:
                    BlacklistedIP.objects.get_or_create(
                        ip_address=ip_address, 
                        defaults={'reason': f"Automated Threat Sync: {score}%"}
                    )
        except Exception:
            pass
        return result

    @staticmethod
    def get_cyber_warfare_news():
        """Hyper-Advanced Intel Engine: RSS Feed Scraper with Multi-Threading"""
        rss_urls = [
            "https://www.bleepingcomputer.com/feed/",
            "https://thehackernews.com/feeds/posts/default"
        ]
        
        raw_items = []
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberOpsSOC/1.0'}

        for url in rss_urls:
            try:
                resp = requests.get(url, headers=headers, timeout=4)
                if resp.status_code == 200:
                    root = ET.fromstring(resp.content)
                    source_key = "BLEEPING_COMPUTER" if "bleeping" in url else "THE_HACKER_NEWS"
                    
                    if source_key == "BLEEPING_COMPUTER":
                        for item in root.findall('.//item')[:4]:
                            title = item.find('title').text if item.find('title') is not None else "CYBER_WARFARE_ALERT"
                            link = item.find('link').text if item.find('link') is not None else "https://www.bleepingcomputer.com"
                            desc_raw = item.find('description').text if item.find('description') is not None else ""
                            pub_date = item.find('pubDate').text if item.find('pubDate') is not None else "Recently"
                            
                            clean_desc = re.sub('<[^<]+?>', '', unescape(desc_raw))[:140] + "..."
                            raw_items.append({
                                "title": title, 
                                "link": link, 
                                "description": clean_desc,
                                "published": pub_date[:16], 
                                "source": "BLEEPING_COMPUTER", 
                                "fallback": "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?q=80&w=500"
                            })
                    else:
                        namespaces = {'atom': 'http://www.w3.org/2005/Atom', 'media': 'http://search.yahoo.com/mrss/'}
                        for entry in root.findall('.//atom:entry', namespaces)[:4]:
                            title = entry.find('atom:title', namespaces).text if entry.find('atom:title', namespaces) is not None else "INTEL_THREAT_UPDATE"
                            link_elem = entry.find('atom:link[@rel="alternate"]', namespaces)
                            link = link_elem.get('href') if link_elem is not None else "https://thehackernews.com"
                            content_raw = entry.find('atom:content', namespaces).text if entry.find('atom:content', namespaces) is not None else ""
                            pub_date = entry.find('atom:published', namespaces).text if entry.find('atom:published', namespaces) is not None else "Recently"
                            
                            clean_desc = re.sub('<[^<]+?>', '', unescape(content_raw))[:140] + "..."
                            
                            img_url = None
                            media_thumb = entry.find('.//media:thumbnail', namespaces)
                            if media_thumb is not None:
                                img_url = media_thumb.get('url')

                            raw_items.append({
                                "title": title, 
                                "link": link, 
                                "description": clean_desc,
                                "published": pub_date[:10], 
                                "source": "THE_HACKER_NEWS", 
                                "image": img_url, 
                                "fallback": "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?q=80&w=500"
                            })
            except Exception as e:
                print(f"[-] Parsing error: {e}")

        def fetch_og_image(item):
            if item.get("image"):
                return item
            try:
                article_resp = requests.get(item["link"], headers=headers, timeout=3)
                if article_resp.status_code == 200:
                    html_content = article_resp.text
                    og_match = re.search(r'<meta[^>]*property=["\']og:image["\'][^>]*content=["\']([^"\']+)["\']', html_content)
                    if not og_match:
                        og_match = re.search(r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*property=["\']og:image["\']', html_content)
                    if og_match:
                        item["image"] = og_match.group(1)
                        return item
            except Exception:
                pass
            item["image"] = item["fallback"]
            return item

        intel_feeds = []
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = executor.map(fetch_og_image, raw_items)
            for res in results:
                intel_feeds.append(res)

        if not intel_feeds:
            intel_feeds = [{
                "title": "Emergency Feed Active", 
                "link": "#", 
                "description": "No stream links parsed.", 
                "published": "Now", 
                "image": "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?q=80&w=500", 
                "source": "SYSTEM"
            }]

        return intel_feeds


class DeepForensicAnalyzer:
    """
    Advanced SOC Forensic Log & Packet Decoder for CYBEROPS.
    Parses PCAP/PCAPNG, EVTX, and server logs to highlight
    suspicious activities, security violations, and CTF flags.
    Features: unencrypted credential leaks extraction, process telemetry,
    port scan heuristics, and interactive console logs.
    """

    @classmethod
    def analyze_forensics(cls, file_name, raw_bytes):
        import os as _os
        file_ext = _os.path.splitext(file_name)[1].lower()
        file_size_bytes = len(raw_bytes)
        file_size_str = f"{file_size_bytes / 1024:.1f} KB" if file_size_bytes < 1048576 else f"{file_size_bytes / 1048576:.2f} MB"
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

        # Telemetry logs for the premium UI hacker console
        console_logs = [
            f"[SYSTEM] // INITIALIZING DEEP FORENSIC SCANNER v4.2 //",
            f"[SYSTEM] File Targeted: {file_name} ({file_size_str})",
            f"[SYSTEM] Hashing payload to calculate integrity signature...",
            f"[INTEGRITY] SHA-256: {sha256_hash}",
            f"[SYSTEM] Reading binary file magic signatures..."
        ]

        ctf_flags = cls._extract_ctf_flags(raw_bytes)
        if ctf_flags:
            console_logs.append(f"[HEURISTIC] [!] Flag-like string matched! Extracted {len(ctf_flags)} flag candidate(s).")

        analysis_type = 'generic'
        result_data = {}

        pcap_magic = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4')
        pcapng_magic = (b'\x0a\x0d\x0d\x0a',)

        # Analyze file structure
        if raw_bytes[:4] in pcap_magic or file_ext == '.pcap':
            analysis_type = 'pcap'
            console_logs.append("[DECODER] Recognized classic PCAP network capture format. Initializing packet dissection...")
            result_data = cls._parse_pcap_deep(raw_bytes, is_pcapng=False, console_logs=console_logs)
        elif raw_bytes[:4] in pcapng_magic or file_ext == '.pcapng':
            analysis_type = 'pcapng'
            console_logs.append("[DECODER] Recognized next-gen PCAPNG network capture format. Dissecting blocks...")
            result_data = cls._parse_pcap_deep(raw_bytes, is_pcapng=True, console_logs=console_logs)
        elif raw_bytes[:7] == b'ElfFile' or file_ext == '.evtx' or b'XML' in raw_bytes[:50] or b'Event' in raw_bytes[:50]:
            analysis_type = 'evtx'
            console_logs.append("[DECODER] Recognized Windows Event Log XML/EVTX payload. Parsing system and security events...")
            result_data = cls._parse_evtx_deep(raw_bytes, console_logs=console_logs)
        elif file_ext in ('.log', '.txt') or any(b in raw_bytes[:100].lower() for b in [b'get /', b'post /', b'http/', b'clientip']):
            analysis_type = 'log'
            console_logs.append("[DECODER] Recognized server log payload. Initiating text signature scanners...")
            result_data = cls._parse_log_deep(raw_bytes, console_logs=console_logs)
        else:
            analysis_type = 'generic'
            console_logs.append("[DECODER] Unknown binary format. Performing generic hexadecimal/string analytics...")
            result_data = {
                'file_type': 'Generic Raw Hex Dump',
                'risk_score': 0,
                'total_events': 0,
                'security_alerts': [],
                'timeline': [],
                'mitigation': "Generic binary file structure. Keep systems updated and inspect payload origin."
            }

        risk_score = result_data.get('risk_score', 0)
        if ctf_flags:
            risk_score = max(risk_score, 45)
        risk_score = min(risk_score, 100)

        if risk_score > 75:
            verdict = 'danger'
            console_logs.append(f"[VERDICT] [CRITICAL] Danger level detected. System compromise indicators verified. Threat Index: {risk_score}%")
        elif risk_score > 30:
            verdict = 'suspicious'
            console_logs.append(f"[VERDICT] [WARNING] Suspicious behaviors observed. Potential recon or misconfigurations. Threat Index: {risk_score}%")
        else:
            verdict = 'clean'
            console_logs.append(f"[VERDICT] [SUCCESS] Clean scan. No malicious exploit or security violation detected. Threat Index: {risk_score}%")

        console_logs.append(f"[SYSTEM] Scanning successfully completed. Dispatching report details to SOC console.")

        return {
            'file_name': file_name,
            'file_size': file_size_str,
            'sha256': sha256_hash,
            'verdict': verdict,
            'risk_score': risk_score,
            'analysis_type': analysis_type,
            'ctf_flags': ctf_flags,
            'file_type': result_data.get('file_type', 'Binary Data'),
            'metrics': result_data,
            'security_alerts': result_data.get('security_alerts', []),
            'timeline': result_data.get('timeline', []),
            'malicious_count': result_data.get('malicious_count', 0),
            'suspicious_count': result_data.get('suspicious_count', 0),
            'console_logs': console_logs,
            'mitigation': result_data.get('mitigation', "No immediate remediation action is required. Maintain baseline security policies.")
        }

    @classmethod
    def _extract_ctf_flags(cls, raw_bytes):
        flags = set()
        text = raw_bytes.decode('latin-1', errors='ignore')
        patterns = [
            r'(?i)(?:flag|cyberops|ctf)\{[A-Za-z0-9_\-\.!@#$%^&*()\+=/?]+\}',
            r'flag_[a-zA-Z0-9_\-]{8,32}',
            r'FLAG_[a-zA-Z0-9_\-]{8,32}',
        ]
        for pat in patterns:
            for match in re.findall(pat, text):
                flags.add(match)
        return list(flags)

    @classmethod
    def _parse_log_deep(cls, raw_bytes, console_logs):
        try:
            text = raw_bytes.decode('utf-8', errors='ignore')
        except Exception:
            text = raw_bytes.decode('latin-1', errors='ignore')

        lines = text.strip().split('\n')
        total_lines = len(lines)
        console_logs.append(f"[LOG_ENGINE] Loaded {total_lines} lines of logs for signature matching.")

        http_codes = Counter()
        endpoints = Counter()
        src_ips = Counter()
        security_alerts = []
        timeline = []

        # Sophisticated vulnerability signature database
        sqli = re.compile(r"(?:union\s+all\s+select|union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table|select\s+.*\s+from\s+|benchmark\s*\(|sleep\s*\(|pg_sleep|information_schema)", re.IGNORECASE)
        path_trav = re.compile(r'(?:\.\.[\\/]|%2e%2e[\\/]|%252e%252e|etc/passwd|etc/shadow|etc/hosts|win\.ini|boot\.ini|/windows/|environ)', re.IGNORECASE)
        xss = re.compile(r'(?:<script|javascript:|onerror\s*=|onload\s*=|eval\s*\(|<iframe|alert\(|String\.fromCharCode)', re.IGNORECASE)
        rce = re.compile(r'(?:;\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh|python|perl|ruby|uname)|\|\s*(?:cat|ls|id|whoami|powershell)|nc\s+-e\s+|/bin/bash|/bin/sh|powershell\.exe|cmd\.exe|Invoke-WebRequest|/etc/issue)', re.IGNORECASE)
        ssrf = re.compile(r'(?:169\.254\.169\.254|localhost|127\.0\.0\.1|0\.0\.0\.0|http://metadata)', re.IGNORECASE)
        scanners = re.compile(r'(?:sqlmap|nmap|nikto|dirbuster|gobuster|hydra|acunetix|masscan|w3af|zgrab|nessus)', re.IGNORECASE)
        brute_force = re.compile(r'(?:Failed\s+password|authentication\s+failure|invalid\s+(?:user|password)|login\s+failed|access\s+denied|wp-login\.php|/admin/login)', re.IGNORECASE)
        
        http_code_pattern = re.compile(r'\s(\d{3})\s')
        endpoint_pattern = re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s"]+)')
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        time_pattern = re.compile(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})[^\]]*\]|(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})')

        malicious_count = 0
        suspicious_count = 0
        scanner_detected = False

        for i, line in enumerate(lines[:1500]):
            line_num = i + 1
            ip_match = ip_pattern.search(line)
            ip = ip_match.group(1) if ip_match else '127.0.0.1'
            if ip_match:
                src_ips[ip] += 1
            
            code_match = http_code_pattern.search(line)
            code = code_match.group(1) if code_match else None
            if code:
                http_codes[code] += 1
            
            ep_match = endpoint_pattern.search(line)
            ep = ep_match.group(1) if ep_match else 'N/A'
            if ep_match:
                endpoints[ep] += 1
            
            date_match = time_pattern.search(line)
            timestamp = 'N/A'
            if date_match:
                timestamp = date_match.group(1) or date_match.group(2) or 'N/A'

            line_alert = None
            
            # Check attack vectors
            if rce.search(line):
                malicious_count += 1
                line_alert = {'line': line_num, 'type': 'RCE Attempt', 'severity': 'critical', 'message': f'Command injection payload detected: {line[:140]}', 'ip': ip, 'timestamp': timestamp}
            elif sqli.search(line):
                malicious_count += 1
                line_alert = {'line': line_num, 'type': 'SQL Injection', 'severity': 'critical', 'message': f'SQLi payload detected: {line[:140]}', 'ip': ip, 'timestamp': timestamp}
            elif path_trav.search(line):
                malicious_count += 1
                line_alert = {'line': line_num, 'type': 'Path Traversal', 'severity': 'critical', 'message': f'LFI path traversal payload: {line[:140]}', 'ip': ip, 'timestamp': timestamp}
            elif ssrf.search(line) and ("http" in line.lower() or "metadata" in line.lower()):
                suspicious_count += 1
                line_alert = {'line': line_num, 'type': 'SSRF Attempt', 'severity': 'warning', 'message': f'Metadata server SSRF attempt: {line[:140]}', 'ip': ip, 'timestamp': timestamp}
            elif scanners.search(line):
                suspicious_count += 1
                scanner_detected = True
                line_alert = {'line': line_num, 'type': 'Scanner Activity', 'severity': 'warning', 'message': f'Automated hacking tool signature: {line[:140]}', 'ip': ip, 'timestamp': timestamp}
            elif xss.search(line):
                suspicious_count += 1
                line_alert = {'line': line_num, 'type': 'XSS Payload', 'severity': 'warning', 'message': f'Cross-site scripting snippet: {line[:140]}', 'ip': ip, 'timestamp': timestamp}
            elif brute_force.search(line):
                suspicious_count += 1
                line_alert = {'line': line_num, 'type': 'Auth Failure', 'severity': 'warning', 'message': f'Failed authentication indicator: {line[:140]}', 'ip': ip, 'timestamp': timestamp}

            if line_alert:
                security_alerts.append(line_alert)
                timeline.append({'index': line_num, 'time': timestamp, 'source': ip, 'type': 'ALERT', 'detail': line_alert['message'], 'severity': line_alert['severity']})
            elif ep != 'N/A' or code:
                timeline.append({'index': line_num, 'time': timestamp, 'source': ip, 'type': 'REQUEST', 'detail': f'"{ep}" -> HTTP {code or "N/A"}', 'severity': 'info'})

        # Dynamically formulate actionable advice
        mitigations = []
        if malicious_count > 0:
            mitigations.append("Strict Input Parameterization: Sanitize HTTP GET/POST queries using standardized whitelists. Do not pass string inputs directly to shell executes or SQL queries.")
        if "SQL Injection" in [a['type'] for a in security_alerts]:
            mitigations.append("SQL Parameterization: Migrate database interfaces to ORMs or prepared statements. Enforce strict typecasting on primary keys.")
        if "RCE Attempt" in [a['type'] for a in security_alerts]:
            mitigations.append("Process Sandboxing: Disable system execution functions (e.g., shell_exec, system, eval) and implement a secure application firewall (WAF).")
        if scanner_detected:
            mitigations.append("Traffic Rate Limiting: Implement smart firewall rules to block IPs generating massive quantities of 404 responses or carrying scanner headers.")
        
        mitigation_text = " // ".join(mitigations) if mitigations else "Maintain normal security monitoring. Review access logs periodically for irregular payloads."

        risk_score = 5 + (malicious_count * 15) + (suspicious_count * 6)
        if http_codes.get('403', 0) > 15:
            risk_score += 15
        if http_codes.get('500', 0) > 8:
            risk_score += 20
        risk_score = min(risk_score, 100)

        console_logs.append(f"[LOG_ENGINE] Completed analyzing access/server log.")
        console_logs.append(f"[LOG_ENGINE] Extracted {malicious_count} Critical exploits and {suspicious_count} Warnings.")

        return {
            'file_type': 'Server Text / Access Log',
            'risk_score': risk_score,
            'total_lines': total_lines,
            'http_codes': dict(http_codes.most_common(10)),
            'top_endpoints': dict(endpoints.most_common(15)),
            'top_src_ips': dict(src_ips.most_common(10)),
            'security_alerts': security_alerts[:150],
            'timeline': timeline[:250],
            'malicious_count': malicious_count,
            'suspicious_count': suspicious_count,
            'mitigation': mitigation_text
        }

    @classmethod
    def _parse_evtx_deep(cls, raw_bytes, console_logs):
        event_id_counts = Counter()
        security_alerts = []
        timeline = []
        
        # Enhanced security event identifier map
        SECURITY_EVENT_MAP = {
            '4624': ('Successful Logon', 'info'),
            '4625': ('Failed Logon Attempt (Possible Brute-force)', 'warning'),
            '4648': ('Logon Using Explicit Credentials', 'warning'),
            '4672': ('Special Privileges Assigned to New Session', 'info'),
            '4688': ('New Process Started (Process Telemetry Block)', 'info'),
            '4697': ('New Windows Service Installed (Persistence Mechanism)', 'warning'),
            '4698': ('Scheduled Task Created', 'warning'),
            '4720': ('Windows User Account Created', 'critical'),
            '4722': ('User Account Enabled', 'warning'),
            '4724': ('Password Reset Attempted', 'warning'),
            '4728': ('Member Added to Privileged Security Group', 'critical'),
            '4732': ('Member Added to Local Administrator Group', 'critical'),
            '1102': ('Audit Log Cleared (Malicious Host Intrusion)', 'critical'),
            '104': ('System Event Log Cleared', 'critical'),
            '7045': ('New Service Registered in Windows System', 'critical'),
        }

        try:
            text_content = raw_bytes.decode('utf-16-le', errors='ignore')
        except Exception:
            text_content = raw_bytes.decode('utf-8', errors='ignore')

        event_ids = re.findall(r'EventID[^>]*>\s*(\d{1,5})\s*<', text_content, re.IGNORECASE)
        times = re.findall(r'TimeCreated[^>]*SystemTime=["\']([^"\']+)["\']', text_content, re.IGNORECASE)
        computers = re.findall(r'Computer[^>]*>\s*([^<]+)\s*<', text_content, re.IGNORECASE)
        computer_name = computers[0] if computers else 'CYBEROPS-ENDPOINT'
        
        # Windows command line and malware signature scanners in EID 4688 / process execution logs
        malicious_processes = re.compile(r'(?:mimikatz|psexec|vssadmin\s+delete\s+shadows|wevtutil\s+cl|whoami|nltest|net\s+user\s+/add|net\s+localgroup\s+administrators|lsass\s+dump|procdump|cobaltstrike|metasploit)', re.IGNORECASE)
        powershell_obfuscation = re.compile(r'(?:powershell.*-enc|powershell.*-encodedcommand|frombase64string|bypass.*-nop.*-w\s+hidden|iex.*new-object.*webclient)', re.IGNORECASE)

        malicious_count = 0
        suspicious_count = 0
        audit_cleared = False

        console_logs.append(f"[EVTX_ENGINE] Discovered computer node: {computer_name}")
        console_logs.append(f"[EVTX_ENGINE] Extracted {len(event_ids)} event logs. Scanning against command line threat models...")

        # Process logs
        for idx, eid in enumerate(event_ids[:1500]):
            event_id_counts[eid] += 1
            timestamp = times[idx] if idx < len(times) else 'N/A'
            formatted_time = timestamp[:19].replace('T', ' ') if timestamp != 'N/A' else 'N/A'
            
            # Search for Windows command line signatures inside the raw content of this event segment
            segment = text_content[max(0, text_content.find(eid)-200):min(len(text_content), text_content.find(eid)+1000)] if text_content.find(eid) != -1 else ""
            
            cmd_match = re.search(r'CommandLine[^>]*>\s*([^<]+)\s*<', segment, re.IGNORECASE)
            cmd_line = cmd_match.group(1) if cmd_match else ""

            event_alert = None
            if eid in ('1102', '104'):
                malicious_count += 1
                audit_cleared = True
                event_alert = {'line': idx + 1, 'type': 'Log Cleared', 'severity': 'critical', 'message': f'Windows System/Security event logs were manually cleared! (EID: {eid})', 'ip': computer_name, 'timestamp': formatted_time}
            elif cmd_line and malicious_processes.search(cmd_line):
                malicious_count += 1
                event_alert = {'line': idx + 1, 'type': 'Malicious Command', 'severity': 'critical', 'message': f'Hacktool Command Execution: "{cmd_line[:140]}"', 'ip': computer_name, 'timestamp': formatted_time}
            elif cmd_line and powershell_obfuscation.search(cmd_line):
                malicious_count += 1
                event_alert = {'line': idx + 1, 'type': 'PowerShell Obfuscation', 'severity': 'critical', 'message': f'Obfuscated or Bypass PowerShell payload: "{cmd_line[:140]}"', 'ip': computer_name, 'timestamp': formatted_time}
            elif eid in SECURITY_EVENT_MAP:
                desc, severity = SECURITY_EVENT_MAP[eid]
                if severity == 'critical':
                    malicious_count += 1
                elif severity == 'warning':
                    suspicious_count += 1
                
                msg = f'{desc} (EID: {eid})'
                if cmd_line:
                    msg += f' - Command: {cmd_line[:80]}'
                event_alert = {'line': idx + 1, 'type': f'EventID {eid}', 'severity': severity, 'message': msg, 'ip': computer_name, 'timestamp': formatted_time}

            if event_alert:
                security_alerts.append(event_alert)
                timeline.append({'index': idx + 1, 'time': formatted_time, 'source': computer_name, 'type': 'ALERT', 'detail': event_alert['message'], 'severity': event_alert['severity']})
            else:
                timeline.append({'index': idx + 1, 'time': formatted_time, 'source': computer_name, 'type': 'EVENT', 'detail': f'Event ID {eid} logged on endpoint', 'severity': 'info'})

        # Dynamically formulate actionable advice
        mitigations = []
        if audit_cleared:
            mitigations.append("Log Destruction Countermeasures: Establish offsite immutable syslog or SIEM log forwarding. Investigate host with high priority for active credential dumping.")
        if malicious_count > 0:
            mitigations.append("Restricted Command Policies: Implement AppLocker or Windows Defender Application Control (WDAC) to prevent executing known hacking scripts.")
        if event_id_counts.get('4625', 0) > 10:
            mitigations.append("Account Lockout Policy: Restrict Remote Desktop / Windows auth attempts. Enable Multi-Factor Authentication (MFA).")
        
        mitigation_text = " // ".join(mitigations) if mitigations else "Endpoint appears stable. Monitor administrative actions and group memberships."

        risk_score = 5 + (malicious_count * 20) + (suspicious_count * 8)
        if event_id_counts.get('1102', 0) > 0:
            risk_score += 35
        if event_id_counts.get('4625', 0) > 12:
            risk_score += 20
        risk_score = min(risk_score, 100)

        console_logs.append(f"[EVTX_ENGINE] Audit complete. Flagged EID events: {dict(event_id_counts)}")

        return {
            'file_type': 'Windows Event Log (EVTX)',
            'risk_score': risk_score,
            'total_events': len(event_ids),
            'computer_name': computer_name,
            'event_id_distribution': dict(event_id_counts.most_common(15)),
            'security_alerts': security_alerts[:150],
            'timeline': timeline[:250],
            'malicious_count': malicious_count,
            'suspicious_count': suspicious_count,
            'mitigation': mitigation_text
        }

    @classmethod
    def _parse_pcap_deep(cls, raw_bytes, is_pcapng=False, console_logs=None):
        protocols = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        dst_ports = Counter()
        total_packets = 0
        total_data_bytes = 0
        security_alerts = []
        timeline = []
        
        # Attack signatures in network packets
        admin_cmds = re.compile(r'(whoami|cat\s+/etc|/bin/sh|/bin/bash|powershell|cmd\.exe|systeminfo|ipconfig|id|uname)', re.IGNORECASE)
        shellshock = re.compile(r'\(\)\s*\{\s*:\s*;\s*\}\s*', re.IGNORECASE)
        reverse_ports = {4444, 5555, 1337, 31337, 9999, 6666, 7777}
        
        # Leaked credential databases
        credentials_pattern = re.compile(r'(?:password|passwd|pwd|pass|admin|username|uname|login|sessionid|secret)\s*[:=]\s*([A-Za-z0-9_\-!@#\$%\^&\*\(\)\+=]{3,24})', re.IGNORECASE)
        basic_auth_pattern = re.compile(r'Authorization:\s*Basic\s*([A-Za-z0-9+/=]{4,120})', re.IGNORECASE)

        # Port scanning tracking map: Source IP -> set(destination ports)
        port_scan_map = {}

        try:
            if is_pcapng:
                offset = 0
                while offset + 8 <= len(raw_bytes):
                    block_type, block_len = struct.unpack('<II', raw_bytes[offset:offset+8])
                    if block_len < 12 or offset + block_len > len(raw_bytes):
                        break
                    if block_type == 6 and block_len >= 32:  # Enhanced Packet Block
                        pkt_len = struct.unpack('<I', raw_bytes[offset+20:offset+24])[0]
                        orig_len = struct.unpack('<I', raw_bytes[offset+24:offset+28])[0]
                        pkt_data = raw_bytes[offset+32:offset+32+pkt_len]
                        total_packets += 1
                        total_data_bytes += orig_len
                        cls._pkt_process_advanced(pkt_data, total_packets, protocols, src_ips, dst_ips, dst_ports, admin_cmds, shellshock, reverse_ports, credentials_pattern, basic_auth_pattern, port_scan_map, security_alerts, timeline, 1)
                    offset += block_len
            else:
                if len(raw_bytes) < 24:
                    return {'file_type': 'PCAP', 'risk_score': 10, 'error': 'Truncated PCAP structure', 'total_packets': 0, 'protocols': {}, 'security_alerts': [], 'timeline': []}
                magic = struct.unpack('<I', raw_bytes[:4])[0]
                endian = '>' if magic == 0xa1b2c3d4 else '<'
                network = struct.unpack(f'{endian}I', raw_bytes[20:24])[0]
                offset = 24
                while offset + 16 <= len(raw_bytes):
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', raw_bytes[offset:offset+16])
                    offset += 16
                    if incl_len > 65535 or offset + incl_len > len(raw_bytes):
                        break
                    pkt_data = raw_bytes[offset:offset+incl_len]
                    offset += incl_len
                    total_packets += 1
                    total_data_bytes += orig_len
                    cls._pkt_process_advanced(pkt_data, total_packets, protocols, src_ips, dst_ips, dst_ports, admin_cmds, shellshock, reverse_ports, credentials_pattern, basic_auth_pattern, port_scan_map, security_alerts, timeline, network)
        except Exception as ex:
            console_logs.append(f"[DECODER] [ERROR] Dissection interrupted: {ex}")

        # Post-scan analysis: Verify port scanners
        port_scan_detected = False
        scanners_ips = []
        for src_ip, ports in port_scan_map.items():
            if len(ports) > 15:
                port_scan_detected = True
                scanners_ips.append(src_ip)
                security_alerts.append({
                    'line': 0,
                    'type': 'Network Recon',
                    'severity': 'critical',
                    'message': f'Port scanning detected! Host scanned {len(ports)} unique ports in short progression.',
                    'ip': src_ip,
                    'timestamp': 'Realtime Flow Analysis'
                })
                timeline.append({
                    'index': 0,
                    'time': 'Flow Analytics',
                    'source': src_ip,
                    'type': 'ALERT',
                    'detail': f'Recon Scan: {src_ip} targeted {len(ports)} distinct ports.',
                    'severity': 'critical'
                })

        mal_c = sum(1 for a in security_alerts if a['severity'] == 'critical')
        sus_c = sum(1 for a in security_alerts if a['severity'] == 'warning')
        
        # Actionable security recommendations
        mitigations = []
        if any(a['type'] == 'Unencrypted Password' for a in security_alerts):
            mitigations.append("Cleartext Credential Leakage: Disable unencrypted HTTP, FTP, or Telnet services. Force TLS 1.3 / SSL across all endpoints.")
        if port_scan_detected:
            mitigations.append("Port Scan Protection: Implement firewall connection rate-limiting and dynamic port-knocking protocols to blind malicious sweepers.")
        if mal_c > 0:
            mitigations.append("Payload Filtering: Deploy deep packet inspection (DPI) or an intrusion detection system (Snort/Suricata) to scrub TCP commands.")
        
        mitigation_text = " // ".join(mitigations) if mitigations else "Network capture appears clear of cleartext compromise indicators. Maintain encrypted baseline."

        risk_score = 5 + (mal_c * 15) + (sus_c * 6)
        if port_scan_detected:
            risk_score += 35
        risk_score = min(risk_score, 100)

        console_logs.append(f"[DECODER] Dissected {total_packets} packets successfully.")
        console_logs.append(f"[DECODER] Protocol breakdown: {dict(protocols)}")
        if scanners_ips:
            console_logs.append(f"[DECODER] [!] WARNING: Active network scanner detected from IP: {', '.join(scanners_ips)}")

        return {
            'file_type': 'PCAPNG Network Capture' if is_pcapng else 'PCAP Network Capture',
            'risk_score': risk_score,
            'total_packets': total_packets,
            'total_data_bytes': total_data_bytes,
            'protocols': dict(protocols.most_common(10)),
            'top_src_ips': dict(src_ips.most_common(10)),
            'top_dst_ips': dict(dst_ips.most_common(10)),
            'top_dst_ports': dict(dst_ports.most_common(15)),
            'security_alerts': security_alerts[:150],
            'timeline': timeline[:250],
            'malicious_count': mal_c,
            'suspicious_count': sus_c,
            'mitigation': mitigation_text
        }

    @classmethod
    def _pkt_process_advanced(cls, pkt_data, pkt_idx, protocols, src_ips, dst_ips, dst_ports, admin_cmds, shellshock, reverse_ports, credentials_pattern, basic_auth_pattern, port_scan_map, security_alerts, timeline, network):
        # We only process Ethernet frames carrying IPv4 traffic
        if len(pkt_data) < 34 or network != 1:
            return
        
        eth_type = struct.unpack('!H', pkt_data[12:14])[0]
        if eth_type == 0x0800:  # IPv4
            ip_hdr = pkt_data[14:]
            if len(ip_hdr) < 20:
                return
            ihl = (ip_hdr[0] & 0x0F) * 4
            proto = ip_hdr[9]
            src_ip = '.'.join(str(b) for b in ip_hdr[12:16])
            dst_ip = '.'.join(str(b) for b in ip_hdr[16:20])
            
            src_ips[src_ip] += 1
            dst_ips[dst_ip] += 1

            if proto == 6:  # TCP
                protocols['TCP'] += 1
                if len(ip_hdr) >= ihl + 4:
                    sp = struct.unpack('!H', ip_hdr[ihl:ihl+2])[0]
                    dp = struct.unpack('!H', ip_hdr[ihl+2:ihl+4])[0]
                    dst_ports[dp] += 1
                    
                    # Track destination port to check for scanning activity
                    if src_ip not in port_scan_map:
                        port_scan_map[src_ip] = set()
                    port_scan_map[src_ip].add(dp)

                    tcp_pay = ip_hdr[ihl+20:]
                    if tcp_pay:
                        decoded = tcp_pay.decode('latin-1', errors='ignore')
                        
                        # 1. Check for command execution scripts
                        if admin_cmds.search(decoded):
                            security_alerts.append({
                                'line': pkt_idx,
                                'type': 'Interactive Shell',
                                'severity': 'critical',
                                'message': f'Admin terminal command in cleartext TCP session: {src_ip}->{dst_ip}:{dp}',
                                'ip': src_ip,
                                'timestamp': f'Pkt #{pkt_idx}'
                            })
                        
                        # 2. Check for shellshock shell inject
                        if shellshock.search(decoded):
                            security_alerts.append({
                                'line': pkt_idx,
                                'type': 'Shellshock Exploit',
                                'severity': 'critical',
                                'message': f'Shellshock payload in HTTP headers: {src_ip}->{dst_ip}:{dp}',
                                'ip': src_ip,
                                'timestamp': f'Pkt #{pkt_idx}'
                            })

                        # 3. Check for CTF Flags
                        flag_match = re.search(r'(?i)((?:flag|cyberops|ctf)\{[^\}]+\})', decoded)
                        if flag_match:
                            security_alerts.append({
                                'line': pkt_idx,
                                'type': 'CTF Flag Captured',
                                'severity': 'info',
                                'message': f'CTF flag matched in network frame: {flag_match.group(1)}',
                                'ip': src_ip,
                                'timestamp': f'Pkt #{pkt_idx}'
                            })

                        # 4. Check for Basic Auth Leakage
                        basic_auth_match = basic_auth_pattern.search(decoded)
                        if basic_auth_match:
                            import base64
                            try:
                                encoded_str = basic_auth_match.group(1)
                                decoded_creds = base64.b64decode(encoded_str).decode('utf-8', errors='ignore')
                                security_alerts.append({
                                    'line': pkt_idx,
                                    'type': 'Unencrypted Password',
                                    'severity': 'critical',
                                    'message': f'HTTP Basic Credentials exposed! Plaintext: "{decoded_creds}"',
                                    'ip': src_ip,
                                    'timestamp': f'Pkt #{pkt_idx}'
                                })
                            except Exception:
                                pass

                        # 5. Check for plain passwords in queries or forms
                        creds_match = credentials_pattern.search(decoded)
                        if creds_match and ("post" in decoded.lower() or "get" in decoded.lower() or "login" in decoded.lower()):
                            security_alerts.append({
                                'line': pkt_idx,
                                'type': 'Unencrypted Password',
                                'severity': 'critical',
                                'message': f'Unencrypted credentials in form submission: "{creds_match.group(0)}"',
                                'ip': src_ip,
                                'timestamp': f'Pkt #{pkt_idx}'
                            })

                    # Port security alarm
                    if dp in reverse_ports or sp in reverse_ports:
                        security_alerts.append({
                            'line': pkt_idx,
                            'type': 'Reverse Shell Port',
                            'severity': 'critical',
                            'message': f'High-risk port association matched (Port {dp} / {sp}). Shell handshake signature!',
                            'ip': src_ip,
                            'timestamp': f'Pkt #{pkt_idx}'
                        })

                    timeline.append({'index': pkt_idx, 'time': f'Pkt #{pkt_idx}', 'source': src_ip, 'type': 'TCP', 'detail': f'TCP Stream: {src_ip}:{sp} -> {dst_ip}:{dp}', 'severity': 'info'})
            
            elif proto == 17:  # UDP
                protocols['UDP'] += 1
                if len(ip_hdr) >= ihl + 4:
                    sp = struct.unpack('!H', ip_hdr[ihl:ihl+2])[0]
                    dp = struct.unpack('!H', ip_hdr[ihl+2:ihl+4])[0]
                    dst_ports[dp] += 1
                    
                    udp_pay = ip_hdr[ihl+8:]
                    if dp == 53 and len(udp_pay) > 100:  # DNS Tunneling indicators
                        security_alerts.append({
                            'line': pkt_idx,
                            'type': 'DNS Tunneling',
                            'severity': 'warning',
                            'message': f'Abnormally large DNS payload ({len(udp_pay)} bytes). Possible DNS data extraction!',
                            'ip': src_ip,
                            'timestamp': f'Pkt #{pkt_idx}'
                        })

                    timeline.append({'index': pkt_idx, 'time': f'Pkt #{pkt_idx}', 'source': src_ip, 'type': 'UDP', 'detail': f'UDP Datagram: {src_ip}:{sp} -> {dst_ip}:{dp}', 'severity': 'info'})
            
            elif proto == 1:  # ICMP
                protocols['ICMP'] += 1
                timeline.append({'index': pkt_idx, 'time': f'Pkt #{pkt_idx}', 'source': src_ip, 'type': 'ICMP', 'detail': f'ICMP Echo request from host {src_ip}', 'severity': 'warning'})
        
        elif eth_type == 0x0806:  # ARP
            protocols['ARP'] += 1
        elif eth_type == 0x86DD:  # IPv6
            protocols['IPv6'] += 1

