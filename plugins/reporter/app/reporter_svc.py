import json
import uuid

import os
from socket import getfqdn
from aiohttp import web
from aiohttp_jinja2 import template

from app.service.auth_svc import check_authorization

# import of own modules
from plugins.reporter.app.detectionreport import create_detection
from plugins.reporter.app.CSVreport import create_csv

##########################################
#### ---------- PARAMETERS ---------- ####
##########################################

class ReporterService:

    def __init__(self, services, domain=getfqdn().split('.', 1)[1]):
        self.services = services
        self.auth_svc = self.services.get('auth_svc')
        self.data_svc = self.services.get('data_svc')
        self.rest_svc = self.services.get('rest_svc')
        self.domain = domain
        self.path = os.path.dirname(os.path.abspath(__file__)).split('reporter', 1)[0] + 'reporter/'

    @template('reporter.html')
    async def splash(self, request):
        await self.auth_svc.check_permissions(request)
        operations = [o.display for o in await self.data_svc.locate('operations')]
        reports = []
        for filename in os.listdir(self.path + 'detectionreports'):
            with open(self.path + 'detectionreports/' + filename) as f:
                data = json.load(f)
            reports.append({
                'id': data['run_id'],
                'name': data['settings']['testname'] + ': ' + data['settings']['host'] + '(' + data['settings']['platform'] + ')',
                'start': data['start']
            })
        return dict(operations=sorted(operations, key=lambda o: o['name']), reports=reports)

    @check_authorization
    async def detectionreport(self, request):
        request_body = json.loads(await request.read())
        report_answer = await self.rest_svc.display_operation_report({'op_id': request_body['operation_id'], 'agent_output':'1'})
        
        jsonreports = create_detection(report_answer, self.domain, self.path, request_body['tanium'], request_body['cortex'], request_body['qradar'])

        return web.json_response(jsonreports)

    @check_authorization
    async def csvexport(self, request):
        request_body = json.loads(await request.read())

        csvreport = create_csv(request_body['report_id'], self.path)

        return web.Response(body=csvreport.encode())
    
