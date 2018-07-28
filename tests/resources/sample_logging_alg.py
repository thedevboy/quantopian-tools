def initialize(context):
    log.error('error')
    log.warn('warn')
    log.debug('debug')
    log.info('info')
    print('print')


def before_trading_start(context, data):
    log.info('info')


def handle_data(context, data):
    log.info('info')
