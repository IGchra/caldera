from aiohttp_jinja2 import template, web
import base64
import json

name = 'Abilities'
description = 'A sample plugin for demonstration purposes'
address = '/plugin/abilities/gui'

async def enable(services):
    app = services.get('app_svc').application
    fetcher = AbilityFetcher(services)
    app.router.add_route('*', '/plugin/abilities/gui', fetcher.splash)
    app.router.add_static('/abilities', 'plugins/abilities/static/', append_version=True)
    app.router.add_route('POST', '/plugin/abilities/csv', fetcher.generate_csv)
    #app.router.add_route('GET', '/get/abilities', fetcher.get_abilities)


class AbilityFetcher:
    def __init__(self, services):
        self.services = services
        self.auth_svc = services.get('auth_svc')

    #async def get_abilities(self, request):
    #    abilities = await self.services.get('data_svc').locate('abilities')
    #    return web.json_response(dict(abilities=[a.display for a in abilities]))
    
    async def generate_csv(self, request):
        #request_body = json.loads(await request.read())
        await self.auth_svc.check_permissions(request)

        ab = await self.get_abilities()
        #for a in ab["abilities"]:
        #    
        # print(a["name"])


        #print("check")
        ##ability_functions = dict(
        #            adversary=lambda d: self._get_adversary_abilities(d),
        #            all=lambda d: self._get_all_abilities())

        #display_name, description, abilities = await ability_functions[request_body['index']](request_body)
        #layer = self._get_layer_boilerplate(name=display_name, description=description)

        #for ability in abilities:
        #        technique = dict(techniqueID=ability.technique_id,tactic=ability.tactic,
        #                           score=1,color='', comment='',enabled=True)
        #        layer['techniques'].append(technique)

        output = ""
        for i, k in enumerate(ab["abilities"][0].keys()):
            if i >= 1:
                output += '§' + k #+ '\"'
            else:
                output += k #+ '\"'
        
        output += '\n'

        for a in ab["abilities"]:
            for i, k in enumerate(a.keys()):
                if i >= 1:
                    output += '§' + '€'.join(str(a[k]).splitlines()) #+ '\"'
                
                else:
                    output += '€'.join(str(a[k]).splitlines())# + '\"'
            output +='\n'

        #print(output)
        return web.Response(body=output.encode())#output)
        #return web.json_response(dict(out=output))
            

        #return web.json_response(ab["abilities"])


    async def get_abilities(self, category='all', term=''):
        abilities = await self.services.get('data_svc').locate('abilities')
        categories=['ability_tag', 'ability_id', 'name', 'description', 'executor', 'test', 'technique_id', 'technique_name', 'tactic', 'payload', 'cleanup', 'platform']
        if len(abilities) == 0:
            return dict(abilities=[], categories=categories, term='No abilities found', category='Select a category')

        encoding = 'utf-8'
        ab_trans = []
        if category == 'all' and term == '':
            for a in abilities:
                a_trans = {}

                #Show the following attributes:
                #ability_tag,ability_id,name, description,test,technique_id,technique_name,tactic,payload,cleanup,executor,platform
                #filter out these: id,unique,parsers,requirements,privilege,timeout
                if str(a.display["description"]).startswith('('):
                    endindex = a.display['description'].index(')')
                    a_trans["ability_tag"] = a.display["description"][1:endindex]
                else:
                    a_trans["ability_tag"] = 'None'
                a_trans["ability_id"] = a.display["ability_id"]
                a_trans["name"]=a.display["name"]
                a_trans["description"]=a.display["description"]
                a_trans["executor"]=a.display["executor"]
                a_trans["test"]=a.display["test"]
                a_trans["technique_id"]=a.display["technique_id"]
                a_trans["technique_name"]=a.display["technique_name"]
                a_trans["tactic"]=a.display["tactic"]
                a_trans["payload"]=a.display["payload"]
                a_trans["cleanup"]=a.display["cleanup"]
                a_trans["platform"]=a.display["platform"]
                ab_trans.append(a_trans)

                #Base64 Decode of command and cleanup
                ab_trans[-1]["test"] = base64.b64decode(ab_trans[-1]["test"]).decode(encoding)
                ab_trans[-1]["cleanup"] = base64.b64decode(ab_trans[-1]["cleanup"]).decode(encoding)
                #print(ab_trans[-1]["test"])
            category = 'Select a category'
            term = 'Search'
        else:
            for a in abilities:
                a_trans = {}

                #Show the following attributes:
                #tag,ability_id,name, description,test,technique_id,technique_name,tactic,cleanup,executor,platform
                #filter out these: id,unique,parsers,requirements,privilege,timeout
                if str(a.display["description"]).startswith('('):
                    endindex = a.display['description'].index(')')
                    a_trans["ability_tag"] = a.display["description"][1:endindex]
                else:
                    a_trans["ability_tag"] = 'None'
                a_trans["ability_id"] = a.display["ability_id"]
                a_trans["name"]=a.display["name"]
                a_trans["description"]=str(a.display["description"])
                a_trans["executor"]=a.display["executor"]
                a_trans["test"]=base64.b64decode(a.display["test"]).decode(encoding)
                a_trans["technique_id"]=a.display["technique_id"]
                a_trans["technique_name"]=a.display["technique_name"]
                a_trans["tactic"]=a.display["tactic"]
                a_trans["payload"]=a.display["payload"]
                a_trans["cleanup"]=base64.b64decode(a.display["cleanup"]).decode(encoding)
                a_trans["platform"]=a.display["platform"]
                if term in a_trans[category]:
                    ab_trans.append(a_trans)
            category = category
            term = term
        return dict(abilities=ab_trans, categories=categories, term=term, category=category)

    @template('abilities.html')
    async def splash(self, request):
        await self.auth_svc.check_permissions(request)
        if 'category' in request.query and 'term' in request.query:
            return await self.get_abilities(request.query['category'], request.query['term'])
        else:
            return await self.get_abilities()

