#!/usr/bin/env python3

import os
import cherrypy
import logging
import time

logging.getLogger("cherrypy").propagate = False
logging.basicConfig(level=logging.INFO, format="%(asctime)s.%(msecs)03d [%(levelname)s] (%(name)s) %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

class Root(object):
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def default(self, *args, **kwargs):
        logging.info("This is an INFO log")
        logging.warning("This is an WARNING log")
        return { 'test' : 'success' }


class Sleep(object):
    exposed = True

    @cherrypy.tools.json_out()
    def GET(self, **params):
        logging.info("Sleep start")
        time.sleep(660)
        logging.info("Sleep finish")
        return { 'sleep' : 'ok' }

class HealthCheck(object):
    exposed = True

    @cherrypy.tools.json_out()
    def GET(self, **params):
        return { 'status' : 'alive' }

def secureheaders():
    headers = cherrypy.response.headers
    headers['server'] = ''
    headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubdomains'
    headers['Content-Security-Policy'] = "default-src 'self' http: https: data: blob: 'unsafe-inline'"
    headers['X-Frame-Options'] = 'SAMEORIGIN'
    headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    headers['X-Content-Type-Options'] = 'nosniff'
    headers['X-XSS-Protection'] = '1; mode=block'

def main():
    root = Root()
    cherrypy.tree.mount(
        HealthCheck(), '/healthy',
        { '/': { 'request.dispatch': cherrypy.dispatch.MethodDispatcher() } }
    )
    cherrypy.tree.mount(
        Sleep(), '/sleep',
        { '/': { 'request.dispatch': cherrypy.dispatch.MethodDispatcher() } }
    )

    cherrypy.tools.secureheaders = cherrypy.Tool('before_finalize', secureheaders, priority=60)

    conf = {
        'global': {
            'server.ssl_certificate' : "certificate.pem",
            'server.ssl_private_key' : "certificate.key",
            'server.socket_host' : '0.0.0.0',
            'server.socket_port' : 8443,
            'tools.proxy.on' : True,
            'tools.proxy.local' : "Host",               # NGINX
            'tools.proxy.remote' : "X-Forwarded-For",
            'tools.proxy.scheme' : 'X-Forwarded-Protocol',
            'engine.autoreload.on': True,
            'tools.secureheaders.on' : True,
            'server.socket_timeout' : 3600
        },
    }

    cherrypy.quickstart(root, '/', conf)

if __name__ == '__main__':
    main()
