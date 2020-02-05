from plugins.importer.app.importer_svc import ImporterService

name = 'importer'
description = 'importer'
address = '/plugin/importer/gui'


async def enable(services):
    app = services.get('app_svc').application
    importer_svc = ImporterService(services)
    app.router.add_static('/importer', 'plugins/importer/static/', append_version=True)
    app.router.add_route('POST', '/plugin/importer/layer', importer_svc.generateAdv)
    app.router.add_route('POST', '/plugin/importer/adversary', importer_svc.create_ability_from_csv)
    app.router.add_route('GET', '/plugin/importer/gui', importer_svc.splash)
