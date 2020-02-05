import json
import uuid
import csv
import os

from datetime import datetime
from io import StringIO
from aiohttp import web
from aiohttp_jinja2 import template

from app.service.auth_svc import check_authorization

def generate_time_stamp():
    time_str = str(datetime.now())
    return time_str[2:4] + time_str[5:7] + time_str[8:10] + time_str[11:13] + time_str[14:16] + time_str[17:19]

def sanity_checks(header):
    try:
        mapper = {
            'name': header.index('name'),
            'description': header.index('description'),
            'executor': header.index('executor'),
            'test': header.index('test'),
            'technique_id': header.index('technique_id'),
            'technique_name': header.index('technique_name'),
            'tactic': header.index('tactic'),
            'cleanup': header.index('cleanup'),
            'platform': header.index('platform'),
            'payload': header.index('payload'),
            'status': 1
        }
        if 'ability_id' in header:
            mapper['ability_id'] = header.index('ability_id')
        else:
            return mapper
    except Exception as err:
        print('Failed' + str(err))
        return {'status': 0}

tactics = ['collection', 'command-and-control', 'credential-access', 'defense-evasion', 'discovery', 'execution', 'exfiltration', 'impact', 'initial-access', 'lateral-movement', 'multiple', 'persistence', 'privilege-escalation', 'technical-information-gathering']

def write_new_adversary(category, os_name, value, path):
    
    filler = max(0, 25 - len(value) - 1)
    filename_adv = 'SEC#'+os_name[:4] + '-' + value[:24] + '-' + filler*'x'
    counter = 1
    with open(path + 'data/adversaries/' + filename_adv + '.yml', 'w') as f:
        f.write('---\n\nid: ' + filename_adv + '\n')
        f.write('name: SEC adversary ' + os_name + ' - '  + category + ' - ' + value + '\n')
        f.write('description: SEC adversary including all abilities for which ' +category + ' starts with ' + value + '\n')
        f.write('visible: 1\n')
        f.write('phases:\n')
        if not os_name == '_all':
            if category == 'all':
                for subdir, dirs, files in os.walk(path + 'data/abilities'):
                    for filename in files:
                        if filename.endswith('.yml') or filename.endswith('.yaml'):
                            try:
                                with open (subdir + '/' + filename) as reading:
                                    line = reading.readline()
                                    while line and not os_name+':' in line:
                                        line = reading.readline()
                                    if line:
                                        f.write('  ' + str(counter) + ':\n')
                                        f.write('    - ' + str(filename[:-4] + '\n'))
                                        counter += 1
                            except Exception as err:
                                print(str(err) + ' ' + str(counter))

            else:
                for subdir, dirs, files in os.walk(path + 'data/abilities'):
                    for filename in files:
                        if filename.endswith('.yaml') or filename.endswith('.yml'):
                            try:
                                os_b = False
                                value_b = False
                                with open (subdir + '/' + filename) as reading:
                                    line = reading.readline()
                                    while line:
                                        while line and not category in line and not os_name + ':' in line:
                                            line = reading.readline()
                                        if line:
                                            if os_name + ':' in line:
                                                os_b = True
                                                line = reading.readline()
                                            elif value in line:
                                                value_b = True
                                                line = reading.readline()
                                            elif ': |' in line:
                                                line = reading.readline()
                                                if value in line:
                                                    value_b = True
                                                    line = reading.readline()
                                            else:
                                                line = reading.readline()
                                    if os_b and value_b:
                                        f.write('  ' + str(counter) + ':\n')
                                        f.write('    - ' + str(filename[:-4] + '\n'))
                                        counter += 1
                                        
                            except Exception as err:
                                print(str(err) + ' ' + str(counter))
        else:
            if category == 'all':
                for subdir, dirs, files in os.walk(path + 'data/abilities'):
                    for filename in files:
                        if filename.endswith('.yml') or filename.endswith('.yaml'):
                            f.write('  ' + str(counter) + ':\n')
                            f.write('    - ' + str(filename)[:-4] + '\n')
                            counter += 1
            else:
                for subdir, dirs, files in os.walk(path + 'data/abilities'):
                    for filename in files:
                        if filename.endswith('.yaml') or filename.endswith('.yml'):
                            try:
                                with open (subdir + '/' + filename) as reading:
                                    line = reading.readline()
                                    while line:
                                        while line and not category in line:
                                            line = reading.readline()
                                        if line:
                                            if value in line:
                                                f.write('  ' + str(counter) + ':\n')
                                                f.write('    - ' + str(filename[:-4] + '\n'))
                                                counter += 1
                                                line = None
                                            elif value in reading.readline():
                                                f.write('  ' + str(counter) + ':\n')
                                                f.write('    - ' + str(filename[:-4] + '\n'))
                                                counter += 1
                                                line = None
                                            else:
                                                line = reading.readline()
                            except Exception as err:
                                print(str(err) + ' ' + str(counter))

        
    if counter == 1:
        os.remove(path + 'data/adversaries/' + filename_adv + '.yml')
        

    return counter


class ImporterService:

    def __init__(self, services):
        self.services = services
        self.auth_svc = self.services.get('auth_svc')
        self.data_svc = self.services.get('data_svc')
        self.rest_svc = self.services.get('rest_svc')
        self.stockpile_path = os.path.dirname(os.path.abspath(__file__)).split('importer', 1)[0] + 'stockpile/'

    @template('importer.html')
    async def splash(self, request):
        await self.auth_svc.check_permissions(request)
        adversaries = [a.display for a in await self.data_svc.locate('adversaries')]
        categories = ['id', 'name', 'description', 'tactic', 'attack_id', 'command', 'cleanup', 'payload']
        return dict(adversaries=sorted(adversaries, key=lambda a: a['name']),categories=categories)

    @check_authorization
    async def generateAdv(self, request):
        
        args = json.loads(await request.read())
        if args['category'] == 'tactic' and args['term'] == '':
            category = 'tactic'
            # Create adversary for each tactic for each os
            for value in tactics:
                write_new_adversary(category, 'windows', value, self.stockpile_path)
                write_new_adversary(category, 'linux', value, self.stockpile_path)
                write_new_adversary(category, 'darwin', value, self.stockpile_path)
            # Create adversary with all (Stable) tests for each os
            write_new_adversary('description', 'windows', '(Stable)', self.stockpile_path)
            write_new_adversary('description', 'linux', '(Stable)', self.stockpile_path)
            write_new_adversary('description', 'darwin', '(Stable)', self.stockpile_path)
            return web.json_response({"status":"successful"})
        else:
            write_new_adversary(args['category'], '_all', args['term'], self.stockpile_path)
            return web.json_response({"Status":"successful"})

    @check_authorization
    async def create_ability_from_csv(self, request):
        """
        Takes a layer file and generates an adversary that matches the selected tactics and techniques.
        Adversary will be divided into phases by tactic
        :param request:
        :return:
        """

        try:
            csv_file = await self.read_csv(request)
        except json.decoder.JSONDecodeError:
            return web.HTTPBadRequest()


        dir_path = os.path.dirname(os.path.realpath(__file__))
        mapping = sanity_checks(next(csv_file))
        if mapping['status'] == 0:
            return web.HTTPBadRequest()
        
        counter = 0
        print('mapping done')
        for ability in csv_file:
            print(ability)
            
            if not len(ability[mapping['technique_id']]) == 5 or not ability[mapping['technique_id']].startswith('T'):
                return web.HTTPBadRequest()
            if not ability[mapping['tactic']] in tactics:
                return web.HTTPBadRequest()
            
            if 'ability_id' in mapping.keys() and not ability[mapping['ability_id']] == '':
                ability_id = ability[mapping['ability_id']]
                print('id in test')
            else:
                ability_id = 'SEC' + ability[mapping['platform']][:3] + 'v1-' + ability[mapping['tactic']][:4] + '-' + ability[mapping['technique_id']][1:] + '-'+ str(counter).zfill(4)+'-' + generate_time_stamp()
                print('id not in test') 

            file_name = self.stockpile_path + 'data/abilities/' + ability[mapping['tactic']] + '/' + ability_id + '.yml'
            try:
                with open(file_name, 'w') as yaml:
                    yaml.write('---\n\n- id: ' + ability_id + '\n')
                    yaml.write('  name: ' + ability[mapping['name']] + '\n')
                    yaml.write('  description: |\n    ' + ability[mapping['description']] + '\n')
                    yaml.write('  tactic: ' + ability[mapping['tactic']] + '\n')
                    yaml.write('  technique:\n')
                    yaml.write('    attack_id: ' + ability[mapping['technique_id']] + '\n')
                    yaml.write('    name: ' + ability[mapping['technique_name']] + '\n')
                    yaml.write('  platforms:\n')
                    yaml.write('    ' + ability[mapping['platform']] + ":\n")
                    yaml.write('      ' + ability[mapping['executor']] + ':\n')
                    yaml.write('        command: |\n')
                    yaml.write('          ' + ability[mapping['test']].replace('€','\n          ') + '\n')
                    if len(ability[mapping['cleanup']]) > 0:
                        yaml.write('        cleanup: |\n')
                        yaml.write('          ' + ability[mapping['cleanup']].replace('€', '\n          ') + '\n')
                    if len(ability[mapping['payload']]) > 0:
                        yaml.write('        payload: ' + ability[mapping['payload']])    
            except Exception as err:
                return web.HTTPBadRequest()
            counter += 1 
        return web.json_response('true')                      
