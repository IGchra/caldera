from plugins.reporter.app.reporter_svc import ReporterService

name = 'Reporter'
description = 'The reporter checks for alerts in detection tools and creates reports'
address = '/plugin/reporter/gui'


async def enable(services):
    app = services.get('app_svc').application
    reporter_svc = ReporterService(services)
    app.router.add_static('/reporter', 'plugins/reporter/static/', append_version=True)
    app.router.add_route('POST', '/plugin/reporter/detectionreport', reporter_svc.detectionreport)
    app.router.add_route('POST', '/plugin/reporter/CSVexport', reporter_svc.csvexport)
    app.router.add_route('GET', '/plugin/reporter/gui', reporter_svc.splash)
