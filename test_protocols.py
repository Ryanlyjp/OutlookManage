import argparse
import base64
import imaplib
import json
import os
import smtplib
import socket
import ssl
import sys
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from email.parser import BytesParser
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse, unquote

import requests
import urllib3

try:
    import socks
except ImportError:
    socks = None

urllib3.disable_warnings()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')
TOKEN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
GRAPH_SCOPE = 'https://graph.microsoft.com/.default'
IMAP_SCOPE = 'https://outlook.office.com/IMAP.AccessAsUser.All offline_access'
POP_SCOPE = 'https://outlook.office.com/POP.AccessAsUser.All offline_access'
SMTP_SCOPE = 'https://outlook.office.com/SMTP.Send offline_access'
GRAPH_ME_URL = 'https://graph.microsoft.com/v1.0/me'
GRAPH_MESSAGES_URL = 'https://graph.microsoft.com/v1.0/me/messages'
GRAPH_SEND_URL = 'https://graph.microsoft.com/v1.0/me/sendMail'
IMAP_HOST = 'outlook.office365.com'
IMAP_PORT = 993
POP_HOST = 'outlook.office365.com'
POP_PORT = 995
SMTP_HOST = 'smtp-mail.outlook.com'
SMTP_PORT = 587
HTTP_TIMEOUT = 30
POLL_INTERVAL_SECONDS = 5
POLL_TIMEOUT_SECONDS = 45
socket_proxy_lock = None


def log(stage, message, level='INFO'):
    print(f'[{stage}][{level}] {time.strftime("%H:%M:%S")} | {message}', file=sys.stderr)


def load_cfg():
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


def parse_account(account_line):
    parts = [part.strip() for part in account_line.strip().split('----')]
    if len(parts) < 4:
        raise ValueError('账号格式错误，必须是 邮箱----密码----client_id----refresh_token')
    email_addr, password, client_id = parts[:3]
    refresh_token = '----'.join(parts[3:]).strip()
    return {
        'email': email_addr,
        'password': password,
        'client_id': client_id,
        'refresh_token': refresh_token,
    }


def build_session(proxy_url):
    session = requests.Session()
    session.verify = False
    if proxy_url:
        session.proxies = {'http': proxy_url, 'https': proxy_url}
    return session


def mask_email(value):
    if not value or '@' not in value:
        return value
    name, domain = value.split('@', 1)
    if len(name) <= 2:
        masked_name = name[:1] + '*'
    else:
        masked_name = name[:2] + '*' * max(1, len(name) - 4) + name[-2:]
    return f'{masked_name}@{domain}'


def mask_secret(value, head=6, tail=4):
    value = str(value or '')
    if len(value) <= head + tail:
        return '*' * len(value)
    return f'{value[:head]}***{value[-tail:]}'


def build_xoauth2(email_addr, access_token):
    payload = f'user={email_addr}\x01auth=Bearer {access_token}\x01\x01'
    return base64.b64encode(payload.encode('utf-8')).decode('ascii')


def decode_jwt_payload(token):
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return {}
        payload = parts[1]
        padding = '=' * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode(payload + padding)
        return json.loads(raw.decode('utf-8'))
    except Exception:
        return {}


def extract_error_text(response):
    try:
        data = response.json()
    except Exception:
        return response.text[:500]
    if isinstance(data, dict):
        return json.dumps(data, ensure_ascii=False)
    return str(data)


def request_refresh_token(session, client_id, refresh_token, scope=None):
    data = {
        'client_id': client_id,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
    }
    if scope:
        data['scope'] = scope
    return session.post(TOKEN_URL, data=data, timeout=HTTP_TIMEOUT)


def get_graph_token(session, client_id, refresh_token):
    attempts = []
    for label, scope in (('default', GRAPH_SCOPE), ('original', None)):
        resp = request_refresh_token(session, client_id, refresh_token, scope=scope)
        details = extract_error_text(resp)[:500] if resp.status_code != 200 else 'success'
        attempts.append({
            'label': label,
            'scope': scope or '(original)',
            'status_code': resp.status_code,
            'details': details,
        })
        if resp.status_code == 200:
            payload = resp.json()
            return {
                'success': True,
                'label': label,
                'scope': scope or '(original)',
                'granted_scope': payload.get('scope', ''),
                'access_token': payload.get('access_token', ''),
                'rotated_refresh_token': payload.get('refresh_token', ''),
                'attempts': attempts,
            }
    return {
        'success': False,
        'error': attempts[-1]['details'] if attempts else 'unknown',
        'attempts': attempts,
    }


def get_protocol_token(session, client_id, refresh_token, scope, protocol):
    resp = request_refresh_token(session, client_id, refresh_token, scope=scope)
    if resp.status_code != 200:
        return {
            'success': False,
            'status_code': resp.status_code,
            'error': extract_error_text(resp)[:500],
        }
    payload = resp.json()
    token = payload.get('access_token', '')
    return {
        'success': bool(token),
        'status_code': resp.status_code,
        'access_token': token,
        'rotated_refresh_token': payload.get('refresh_token', ''),
        'scope': scope,
        'protocol': protocol,
        'raw': payload,
    }


@contextmanager
def proxy_socket_context(proxy_url):
    global socket_proxy_lock
    if not proxy_url:
        yield
        return
    if not socks:
        raise RuntimeError('缺少 PySocks，无法通过代理测试 IMAP/POP/SMTP')
    parsed = urlparse(proxy_url)
    scheme = (parsed.scheme or '').lower()
    proxy_type_map = {
        'socks5': socks.SOCKS5,
        'socks5h': socks.SOCKS5,
        'socks4': socks.SOCKS4,
        'http': socks.HTTP,
        'https': socks.HTTP,
    }
    proxy_type = proxy_type_map.get(scheme)
    if not proxy_type or not parsed.hostname or not parsed.port:
        raise RuntimeError(f'不支持的代理: {proxy_url}')
    username = unquote(parsed.username) if parsed.username else None
    password = unquote(parsed.password) if parsed.password else None
    rdns = scheme == 'socks5h'
    if socket_proxy_lock is None:
        import threading
        socket_proxy_lock = threading.Lock()
    with socket_proxy_lock:
        original_socket = socket.socket
        try:
            socks.set_default_proxy(
                proxy_type,
                parsed.hostname,
                parsed.port,
                username=username,
                password=password,
                rdns=rdns,
            )
            socket.socket = socks.socksocket
            yield
        finally:
            socket.socket = original_socket
            socks.set_default_proxy()


def graph_get(session, access_token, url, params=None):
    return session.get(
        url,
        headers={'Authorization': f'Bearer {access_token}'},
        params=params,
        timeout=HTTP_TIMEOUT,
    )


def graph_post(session, access_token, url, body):
    return session.post(
        url,
        headers={
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
        },
        json=body,
        timeout=HTTP_TIMEOUT,
    )


def test_graph_profile(session, access_token):
    resp = graph_get(session, access_token, GRAPH_ME_URL, params={'$select': 'mail,userPrincipalName,displayName,createdDateTime'})
    result = {'http_status': resp.status_code}
    if resp.status_code == 200:
        data = resp.json()
        result.update({
            'ok': True,
            'mail': data.get('mail') or data.get('userPrincipalName') or '',
            'display_name': data.get('displayName') or '',
            'createdDateTime': data.get('createdDateTime', ''),
        })
        return result
    result.update({'ok': False, 'error': extract_error_text(resp)[:500]})
    return result


def test_graph_read(session, access_token):
    resp = graph_get(
        session,
        access_token,
        GRAPH_MESSAGES_URL,
        params={'$top': 1, '$select': 'id,subject,receivedDateTime'},
    )
    result = {'http_status': resp.status_code}
    if resp.status_code == 200:
        items = resp.json().get('value', [])
        result.update({
            'ok': True,
            'message_count_sample': len(items),
            'latest_subject': items[0].get('subject', '') if items else '',
            'latest_received': items[0].get('receivedDateTime', '') if items else '',
        })
        return result
    result.update({'ok': False, 'error': extract_error_text(resp)[:500]})
    return result


def send_graph_mail(session, access_token, recipients, subject, body_text):
    body = {
        'message': {
            'subject': subject,
            'body': {'contentType': 'Text', 'content': body_text},
            'toRecipients': [
                {'emailAddress': {'address': recipient}}
                for recipient in recipients
            ],
        },
        'saveToSentItems': True,
    }
    resp = graph_post(session, access_token, GRAPH_SEND_URL, body)
    result = {'http_status': resp.status_code}
    if resp.status_code == 202:
        result['ok'] = True
        return result
    result.update({'ok': False, 'error': extract_error_text(resp)[:500]})
    return result


def poll_graph_subject(session, access_token, subject):
    deadline = time.time() + POLL_TIMEOUT_SECONDS
    while time.time() < deadline:
        resp = graph_get(
            session,
            access_token,
            GRAPH_MESSAGES_URL,
            params={'$top': 10, '$select': 'id,subject,receivedDateTime'},
        )
        if resp.status_code == 200:
            for item in resp.json().get('value', []):
                if item.get('subject') == subject:
                    return {
                        'ok': True,
                        'receivedDateTime': item.get('receivedDateTime', ''),
                        'message_id': item.get('id', ''),
                    }
        time.sleep(POLL_INTERVAL_SECONDS)
    return {'ok': False}


def graph_earliest_message(session, access_token):
    queries = [
        ('https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages', {'$top': 1, '$select': 'id,subject,receivedDateTime,from', '$orderby': 'receivedDateTime asc'}),
        (GRAPH_MESSAGES_URL, {'$top': 1, '$select': 'id,subject,receivedDateTime,from', '$orderby': 'receivedDateTime asc'}),
    ]
    errors = []
    for url, params in queries:
        resp = graph_get(session, access_token, url, params=params)
        if resp.status_code == 200:
            items = resp.json().get('value', [])
            if not items:
                return {'ok': True, 'empty': True}
            item = items[0]
            return {
                'ok': True,
                'id': item.get('id', ''),
                'subject': item.get('subject', ''),
                'receivedDateTime': item.get('receivedDateTime', ''),
                'from': (((item.get('from') or {}).get('emailAddress') or {}).get('address') or ''),
            }
        errors.append({
            'url': url,
            'http_status': resp.status_code,
            'error': extract_error_text(resp)[:500],
        })
    return {'ok': False, 'errors': errors}


def _to_iso(value):
    if not value:
        return ''
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def imap_earliest_message(email_addr, access_token, proxy_url):
    ssl_context = ssl.create_default_context()
    auth_payload = f'user={email_addr}\x01auth=Bearer {access_token}\x01\x01'.encode('utf-8')
    with proxy_socket_context(proxy_url):
        conn = None
        try:
            conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=ssl_context, timeout=HTTP_TIMEOUT)
            conn.authenticate('XOAUTH2', lambda _: auth_payload)
            select_type, _ = conn.select('INBOX', readonly=True)
            if select_type != 'OK':
                return {'ok': False, 'error': f'select failed: {select_type}'}
            search_type, search_data = conn.uid('search', None, 'ALL')
            if search_type != 'OK' or not search_data:
                return {'ok': False, 'error': 'search failed'}
            raw = search_data[0].decode('utf-8', errors='ignore') if isinstance(search_data[0], bytes) else str(search_data[0] or '')
            uids = [uid for uid in raw.split() if uid]
            if not uids:
                return {'ok': True, 'empty': True}
            fetch_type, fetch_data = conn.uid('fetch', uids[0], '(BODY.PEEK[HEADER.FIELDS (SUBJECT DATE FROM)])')
            if fetch_type != 'OK' or not fetch_data:
                return {'ok': False, 'error': f'fetch failed: {fetch_type}'}
            header_bytes = b''
            for item in fetch_data:
                if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
                    header_bytes = item[1]
                    break
            parsed = BytesParser().parsebytes(header_bytes)
            try:
                dt = parsedate_to_datetime(parsed.get('Date', ''))
            except Exception:
                dt = None
            return {
                'ok': True,
                'uid': uids[0],
                'subject': parsed.get('Subject', ''),
                'from': parsed.get('From', ''),
                'receivedDateTime': _to_iso(dt),
            }
        except Exception as exc:
            return {'ok': False, 'error': str(exc)}
        finally:
            if conn:
                try:
                    conn.logout()
                except Exception:
                    pass


def infer_registration(profile_result, graph_mail_result, imap_mail_result):
    if profile_result.get('ok') and profile_result.get('createdDateTime'):
        return {
            'registered_at': profile_result.get('createdDateTime', ''),
            'registered_source': 'graph_profile_createdDateTime',
        }
    if graph_mail_result.get('ok') and graph_mail_result.get('receivedDateTime'):
        return {
            'registered_at': graph_mail_result.get('receivedDateTime', ''),
            'registered_source': 'graph_earliest_mail',
        }
    if imap_mail_result.get('ok') and imap_mail_result.get('receivedDateTime'):
        return {
            'registered_at': imap_mail_result.get('receivedDateTime', ''),
            'registered_source': 'imap_earliest_mail',
        }
    return {'registered_at': '', 'registered_source': ''}


def test_imap(email_addr, access_token, proxy_url):
    ssl_context = ssl.create_default_context()
    auth_payload = f'user={email_addr}\x01auth=Bearer {access_token}\x01\x01'.encode('utf-8')
    with proxy_socket_context(proxy_url):
        conn = None
        try:
            conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=ssl_context, timeout=HTTP_TIMEOUT)
            conn.authenticate('XOAUTH2', lambda _: auth_payload)
            select_type, select_data = conn.select('INBOX', readonly=True)
            result = {
                'ok': select_type == 'OK',
                'select_type': select_type,
                'select_data': [part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in (select_data or [])],
            }
            if select_type == 'OK':
                search_type, search_data = conn.uid('search', None, 'ALL')
                uids = []
                if search_type == 'OK' and search_data:
                    raw = search_data[0].decode('utf-8', errors='ignore') if isinstance(search_data[0], bytes) else str(search_data[0])
                    uids = [uid for uid in raw.split() if uid]
                result['uid_count'] = len(uids)
                if uids:
                    fetch_type, fetch_data = conn.uid('fetch', uids[-1], '(BODY.PEEK[HEADER.FIELDS (SUBJECT DATE FROM)])')
                    result['latest_fetch_type'] = fetch_type
                    if fetch_type == 'OK' and fetch_data:
                        header_blob = ''
                        for item in fetch_data:
                            if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
                                header_blob = item[1].decode('utf-8', errors='ignore')
                                break
                        result['latest_header'] = header_blob[:500]
            return result
        finally:
            if conn:
                try:
                    conn.logout()
                except Exception:
                    pass


def recv_line(sock):
    data = b''
    while not data.endswith(b'\r\n'):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode('utf-8', errors='ignore').strip()


def send_line(sock, line):
    sock.sendall(line.encode('utf-8') + b'\r\n')


def test_pop(email_addr, access_token, proxy_url):
    auth_string = build_xoauth2(email_addr, access_token)
    ssl_context = ssl.create_default_context()
    with proxy_socket_context(proxy_url):
        raw_sock = socket.create_connection((POP_HOST, POP_PORT), timeout=HTTP_TIMEOUT)
        ssl_sock = ssl_context.wrap_socket(raw_sock, server_hostname=POP_HOST)
        try:
            greeting = recv_line(ssl_sock)
            send_line(ssl_sock, 'AUTH XOAUTH2')
            challenge = recv_line(ssl_sock)
            send_line(ssl_sock, auth_string)
            auth_resp = recv_line(ssl_sock)
            result = {
                'greeting': greeting,
                'challenge': challenge,
                'auth_response': auth_resp,
                'ok': auth_resp.startswith('+OK'),
            }
            if not result['ok']:
                send_line(ssl_sock, 'QUIT')
                recv_line(ssl_sock)
                return result
            send_line(ssl_sock, 'STAT')
            stat_resp = recv_line(ssl_sock)
            result['stat'] = stat_resp
            send_line(ssl_sock, 'LIST 1')
            result['list_1'] = recv_line(ssl_sock)
            send_line(ssl_sock, 'QUIT')
            result['quit'] = recv_line(ssl_sock)
            return result
        finally:
            try:
                ssl_sock.close()
            except Exception:
                pass


def test_smtp_auth_and_send(email_addr, access_token, recipients, subject, body_text, proxy_url, send_message=True):
    auth_string = build_xoauth2(email_addr, access_token)
    with proxy_socket_context(proxy_url):
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=HTTP_TIMEOUT)
        try:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            code, auth_resp = server.docmd('AUTH', 'XOAUTH2 ' + auth_string)
            result = {
                'auth_code': code,
                'auth_response': auth_resp.decode('utf-8', errors='ignore') if isinstance(auth_resp, bytes) else str(auth_resp),
                'ok': code == 235,
            }
            if not result['ok'] or not send_message:
                return result
            message = EmailMessage()
            message['From'] = email_addr
            message['To'] = ', '.join(recipients)
            message['Subject'] = subject
            message.set_content(body_text)
            refused = server.send_message(message)
            result['send_ok'] = not refused
            result['refused'] = refused
            return result
        finally:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass


def classify_account_health(graph_token_result, profile_result, read_result):
    if not graph_token_result.get('success'):
        error_text = (graph_token_result.get('error') or '').lower()
        if 'invalid_grant' in error_text:
            return 'token_invalid_or_revoked'
        if 'consent' in error_text or 'interaction_required' in error_text:
            return 'consent_or_interaction_required'
        return 'oauth_unavailable'
    if not profile_result.get('ok'):
        return 'graph_profile_failed'
    if read_result.get('ok'):
        return 'normal'
    if read_result.get('http_status') == 403:
        return 'graph_mail_permission_missing'
    return 'mailbox_or_graph_issue'


def run_account_test(account_line, proxy_url='', external_recipient='', skip_send=False, protocol_cfg=None):
    """In-process entry for WebUI: same logic as CLI main(), returns results dict (also prints JSON when CLI)."""
    cfg = load_cfg()
    protocol_cfg = protocol_cfg if protocol_cfg is not None else (cfg.get('protocol_test') or {})
    account = parse_account(account_line)
    proxy_url = (proxy_url or '').strip()
    external_recipient = (external_recipient or '').strip()
    send_enabled = not skip_send and bool(protocol_cfg.get('send_test_mail', True))
    session = build_session(proxy_url)
    timestamp = datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')
    test_subject = f'[OutlookManagement][{datetime.now().strftime("%Y%m%d-%H%M%S")}] protocol test'
    body_text = f'Protocol test generated at {timestamp}.'
    graph_recipients = [account['email']]
    if external_recipient and external_recipient.lower() != account['email'].lower():
        graph_recipients.append(external_recipient)

    results = {
        'timestamp': timestamp,
        'proxy': proxy_url,
        'account': {
            'email_masked': mask_email(account['email']),
            'client_id': account['client_id'],
            'refresh_token_masked': mask_secret(account['refresh_token']),
        },
        'baseline': {},
        'graph': {},
        'protocols': {},
        'registration': {},
    }

    log('BASELINE', '开始 Graph baseline 检测')
    graph_token_result = get_graph_token(session, account['client_id'], account['refresh_token'])
    graph_token_ok = graph_token_result.get('success', False)
    graph_access_token = graph_token_result.get('access_token', '') if graph_token_ok else ''
    jwt_payload = decode_jwt_payload(graph_access_token) if graph_access_token else {}
    graph_scopes = jwt_payload.get('scp', '')

    profile_result = test_graph_profile(session, graph_access_token) if graph_access_token else {'ok': False}
    read_result = test_graph_read(session, graph_access_token) if graph_access_token else {'ok': False}
    graph_earliest_result = graph_earliest_message(session, graph_access_token) if graph_access_token else {'ok': False, 'error': 'graph token unavailable'}
    imap_earliest_result = {}
    if not graph_earliest_result.get('ok'):
        imap_registration_token = get_protocol_token(session, account['client_id'], account['refresh_token'], IMAP_SCOPE, 'imap_registration')
        if imap_registration_token.get('success'):
            imap_earliest_result = imap_earliest_message(account['email'], imap_registration_token.get('access_token', ''), proxy_url)
        else:
            imap_earliest_result = {'ok': False, 'error': imap_registration_token.get('error', '')}
    registration_result = infer_registration(profile_result, graph_earliest_result, imap_earliest_result)
    account_health = classify_account_health(graph_token_result, profile_result, read_result)

    results['baseline'] = {
        'graph_token_ok': graph_token_ok,
        'graph_profile_ok': profile_result.get('ok', False),
        'graph_read_ok': read_result.get('ok', False),
        'account_health': account_health,
        'graph_token_attempts': graph_token_result.get('attempts', []),
        'graph_profile': profile_result,
        'graph_read': read_result,
    }
    results['registration'] = {
        **registration_result,
        'graph_earliest_mail': graph_earliest_result,
        'imap_earliest_mail': imap_earliest_result,
    }

    results['graph'] = {
        'scopes': graph_scopes or graph_token_result.get('granted_scope', ''),
        'jwt_payload_excerpt': {
            'aud': jwt_payload.get('aud', ''),
            'scp': jwt_payload.get('scp', ''),
            'appid': jwt_payload.get('appid', ''),
            'upn': jwt_payload.get('upn', ''),
        },
        'read': read_result,
        'send_recipients_masked': [mask_email(item) for item in graph_recipients],
    }

    if graph_access_token and send_enabled:
        log('GRAPH', '测试 Graph 发信')
        graph_send_result = send_graph_mail(session, graph_access_token, graph_recipients, test_subject, body_text)
        graph_self_receive_poll = poll_graph_subject(session, graph_access_token, test_subject) if graph_send_result.get('ok') else {'ok': False}
    else:
        graph_send_result = {'ok': False, 'skipped': True}
        graph_self_receive_poll = {'ok': False, 'skipped': True}

    results['graph']['send'] = graph_send_result
    results['graph']['self_receive_poll'] = graph_self_receive_poll

    for protocol, scope in (
        ('imap', IMAP_SCOPE),
        ('pop', POP_SCOPE),
        ('smtp', SMTP_SCOPE),
    ):
        log(protocol.upper(), f'申请 {protocol.upper()} token')
        token_result = get_protocol_token(session, account['client_id'], account['refresh_token'], scope, protocol)
        protocol_result = {
            'token_ok': token_result.get('success', False),
            'token_status_code': token_result.get('status_code'),
            'scope': scope,
        }
        if not token_result.get('success'):
            protocol_result['ok'] = False
            protocol_result['error'] = token_result.get('error', '')
            results['protocols'][protocol] = protocol_result
            continue

        access_token = token_result.get('access_token', '')
        try:
            if protocol == 'imap':
                probe = test_imap(account['email'], access_token, proxy_url)
            elif protocol == 'pop':
                probe = test_pop(account['email'], access_token, proxy_url)
            else:
                smtp_recipients = list(graph_recipients)
                probe = test_smtp_auth_and_send(
                    account['email'],
                    access_token,
                    smtp_recipients if send_enabled else [account['email']],
                    test_subject + ' [SMTP]',
                    body_text,
                    proxy_url,
                )
                protocol_result['smtp_recipients_masked'] = [mask_email(item) for item in smtp_recipients]
            protocol_result.update(probe)
        except Exception as exc:
            protocol_result.update({
                'ok': False,
                'error': str(exc),
            })
        if proxy_url and not protocol_result.get('ok'):
            try:
                if protocol == 'imap':
                    protocol_result['direct_diagnostic'] = test_imap(account['email'], access_token, '')
                elif protocol == 'pop':
                    protocol_result['direct_diagnostic'] = test_pop(account['email'], access_token, '')
                else:
                    protocol_result['direct_diagnostic'] = test_smtp_auth_and_send(
                        account['email'],
                        access_token,
                        [account['email']],
                        test_subject + ' [SMTP-DIAG]',
                        body_text,
                        '',
                        send_message=False,
                    )
            except Exception as exc:
                protocol_result['direct_diagnostic'] = {
                    'ok': False,
                    'error': str(exc),
                }
        results['protocols'][protocol] = protocol_result

    results['protocols']['smtp_recipients_masked'] = results['protocols'].get('smtp', {}).get('smtp_recipients_masked', [])

    log('SUMMARY', f"账号状态={account_health} GraphRead={read_result.get('ok')} GraphSend={graph_send_result.get('ok')}")
    log(
        'SUMMARY',
        f"IMAP={results['protocols'].get('imap', {}).get('ok')} POP={results['protocols'].get('pop', {}).get('ok')} "
        f"SMTP_AUTH={results['protocols'].get('smtp', {}).get('ok')} SMTP_SEND={results['protocols'].get('smtp', {}).get('send_ok')}"
    )
    return results


def main():
    cfg = load_cfg()
    protocol_cfg = cfg.get('protocol_test') or {}
    parser = argparse.ArgumentParser(description='Test Graph / IMAP / POP / SMTP availability for one Outlook account.')
    parser.add_argument('--account', required=True, help='邮箱----密码----client_id----refresh_token')
    parser.add_argument('--proxy', default=((cfg.get('proxy') or {}).get('url') or 'http://127.0.0.1:7890').strip())
    parser.add_argument('--external-recipient', default=protocol_cfg.get('external_recipient') or '')
    parser.add_argument('--skip-send', action='store_true')
    args = parser.parse_args()
    results = run_account_test(
        args.account,
        proxy_url=args.proxy,
        external_recipient=args.external_recipient,
        skip_send=args.skip_send,
        protocol_cfg=protocol_cfg,
    )
    print(json.dumps(results, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({
            'fatal_error': str(exc),
            'traceback': traceback.format_exc(limit=20),
        }, ensure_ascii=False))
        raise
