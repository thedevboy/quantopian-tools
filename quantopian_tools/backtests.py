# -*- coding: utf-8 -*-
from __future__ import print_function, absolute_import, division, unicode_literals

import json
from contextlib import closing

import websocket

from quantopian_tools import schema, session
from quantopian_tools.exceptions import RequestError, ResponseValidationError, QuantopianException
from quantopian_tools.helpers import build_url


def log_payload_schema():
    return {
        'count': schema.integer(required=True, nullable=False, min=0, rename='num_lines')
    }


def position_schema():
    return {
        'a': schema.number(required=True, nullable=False, rename='amount'),
        'cb': schema.number(required=True, nullable=False, rename='cost_basis'),
        's': schema.integer(required=True, nullable=False, min=0, rename='sid'),
        'ls': schema.number(required=True, nullable=False, rename='last_sale_price')
    }


def performance_schema():
    return {
        'be': schema.number(required=True, nullable=True, default=None, rename='beta'),
        'al': schema.number(required=True, nullable=True, default=None, rename='alpha'),
        'vo': schema.number(required=True, nullable=True, default=None, rename='volatility'),
        'bv': schema.number(required=True, nullable=True, default=None),  # , rename='bv'),  # TODO: Find actual name
        'pnl': schema.number(required=True, nullable=True, default=None),
        'br': schema.number(required=True, nullable=True, default=None, rename='benchmark_returns'),
        'in': schema.number(required=True, nullable=True, default=None, rename='information_ratio'),
        'cu': schema.number(required=True, nullable=True, default=None, rename='cushion'),
        'md': schema.number(required=True, nullable=True, default=None, rename='max_drawdown'),
        'ml': schema.number(required=True, nullable=True, default=None, rename='max_leverage'),
        'tr': schema.number(required=True, nullable=True, default=None, rename='total_returns'),
        'sh': schema.number(required=True, nullable=True, default=None, rename='sharpe'),
        'so': schema.number(required=True, nullable=True, default=None, rename='sorentino')
    }


def daily_result_schema():
    return {
        'o': schema.list_(required=True, nullable=True, default=None),  # , rename='o'),  # TODO: Find actual name
        'rv': schema.dictionary(required=True, nullable=True, default=None, rename='custom_data'),
        'd': schema.date_(required=True, nullable=True, min=0, default=None, rename='date',
                          coerce=('millis_timestamp', 'datetime_to_date')),
        'c': schema.dictionary(required=True, nullable=True, default=None, rename='performance',
                               schema=performance_schema()),
        'l': schema.number(required=True, nullable=True, default=None, rename='leverage'),
        'ec': schema.number(required=True, nullable=True, default=None, rename='equity_with_loan'),
        'p': schema.list_(required=True, nullable=True, default=None, rename='positions',
                          schema=schema.dictionary(schema=position_schema())),
        'pnl': schema.number(required=True, nullable=True, default=None),
        't': schema.list_(required=True, nullable=True, default=None),  # , rename='t'),  # TODO: Find actual name
        'cb': schema.number(required=True, nullable=True, default=None),  # , rename='t'),  # TODO: Find actual name
        'bm': schema.number(required=True, nullable=True, default=None)  # , rename='t')  # TODO: Find actual name
    }


def performance_payload_schema():
    return {
        'cursor': schema.integer(required=True, nullable=False),
        'pc': schema.number(required=True, nullable=False, rename='percent_complete'),
        'sa': schema.datetime_(required=True, nullable=False, min=0, rename='timestamp', coerce='millis_timestamp'),
        'daily': schema.dictionary(required=True, nullable=True, default=None, rename='daily_performance',
                                   coerce='first_item', schema=daily_result_schema())
    }


def risk_report_payload_schema():
    return {
        'metrics': schema.dictionary(
            required=True,
            nullable=False,
            schema={
                'information': schema.dictionary(required=True, nullable=False),
                'algorithm_period_return': schema.dictionary(required=True, nullable=False),
                'max_drawdown': schema.dictionary(required=True, nullable=False),
                'sortino': schema.dictionary(required=True, nullable=False),
                'algo_volatility': schema.dictionary(required=True, nullable=False),
                'trading_days': schema.dictionary(required=True, nullable=False),
                'max_leverage': schema.dictionary(required=True, nullable=False),
                'benchmark_volatility': schema.dictionary(required=True, nullable=False),
                'beta': schema.dictionary(required=True, nullable=False),
                'excess_return': schema.dictionary(required=True, nullable=False),
                'treasury_period_return': schema.dictionary(required=True, nullable=False),
                'sharpe': schema.dictionary(required=True, nullable=False),
                'alpha': schema.dictionary(required=True, nullable=False),
                'benchmark_period_return': schema.dictionary(required=True, nullable=False)
            }
        )
    }


def stack_schema():
    return {
        'lineno': schema.integer(required=True, nullable=True, min=0),
        'line': schema.string(required=True, nullable=True, empty=True),
        'method': schema.string(required=True, nullable=True, empty=True),
        'filename': schema.string(required=True, nullable=True, empty=True)
    }


def done_payload_schema():
    return {
        'completed_at': schema.datetime_(required=True, nullable=False, coerce='millis_timestamp'),
        'reason': schema.string(required=True, nullable=False)
    }


def exception_payload_schema():
    return {
        'date': schema.datetime_(required=True, nullable=False, rename='timestamp', coerce='millis_timestamp'),
        'message': schema.string(required=True, nullable=False),
        'name': schema.string(required=True, nullable=False),
        'stack': schema.list_(required=True, nullable=False, schema=stack_schema())
    }


def _log_level(value):
    if value is None:
        return None
    return {
        1: 'DEBUG',
        2: 'INFO',
        4: 'WARNING',
        5: 'ERROR',
        10: 'DEBUG',
        11: 'INFO',
        13: 'WARNING',
        14: 'ERROR'
    }.get(value) or 'UNKNOWN'


def start_backtest(algorithm, start_date, end_date, capital_base, data_frequency='minute'):
    url = build_url('backtests', 'start_ide_backtest')
    headers = {
        'x-csrf-token': session.browser.get_csrf_token(build_url('algorithms', algorithm['id'])),
        'x-requested-with': 'XMLHttpRequest'
    }
    data = {
        'algo_id': algorithm['id'],
        'code': algorithm['code'],
        'backtest_start_date_year': start_date.year,
        'backtest_start_date_month': start_date.month,
        'backtest_start_date_day': start_date.day,
        'backtest_end_date_year': end_date.year,
        'backtest_end_date_month': end_date.month,
        'backtest_end_date_day': end_date.day,
        'backtest_capital_base': capital_base,
        'backtest_data_frequency_value': data_frequency
    }
    response = session.browser.post(url, data=data, headers=headers)
    if not response.ok:
        raise RequestError('failed to start backtest', response)

    valid, data_or_errors = schema.validate(response.json(), {
        'data': schema.dictionary(required=True, schema={
            'id': schema.string(required=True, nullable=False, empty=False),
            'debug_open_msg': schema.string(required=True, nullable=False, empty=False),
            'debug_ws_url': schema.string(required=True, nullable=False, empty=False),
            'ws_open_msg': schema.string(required=True, nullable=False, empty=False),
            'ws_url': schema.string(required=True, nullable=False, empty=False)
        })
    }, allow_unknown=True)
    if not valid:
        raise ResponseValidationError('POST', url, algorithm, data_or_errors)
    return data_or_errors['data']


def debug_backtest(backtest):
    """
    Open:
    sent: {
    'e': 'start',
    'p': 'U2FsdGVkX1/F+fCWU4bOM'
         '/RGz9PO6UpGXdQ3eBWa0leZcjfacvfLk23ihYnLi9gmco1EmXQnS1idNnIWatxFNMf8r61FUahwc2iSYkZDYTbkDcjgZLERViD'
         '+TycXjuYIG+32aBCqD3ZAe5UmM3BYpAvI3z9Op/+D+L2s6ltAozZ+3WhXliJJq4WnUPUyx2E0QSS3mDBmAqBsJX92i7kGqA=='
    }
    sent: {'e': 'set_watch', 'p': []}
    sent: {'e': 'set_watch', 'p': ['get_datetime().strftime(\'%Y-%m-%d %H:%M:%S\')#__QUANTOPIAN__']}
    # Hits first BP
    recv: {'p': [], 'e': 'watchlist'}
    recv: {'p': {'index': 0, 'stack': [{'line': 36, 'code': ' schedule_function(rebalance, date_rules.week_start(), time_rules.market_open(hours=1))', 'file': '<algorithm>', 'func': 'initialize'}]}, 'e': 'stack'}
    recv: {'p': [], 'e': 'watchlist'}
    recv: {'p': [{'expr': 'get_datetime().strftime(\'%Y-%m-%d %H:%M:%S\')#__QUANTOPIAN__', 'exc': null, 'value': '{\'truncated\': 0, \'context\': null, \'objtype\': \'str\', \'nodes\': [], \'data\': \'2016-01-04 00:00:00\', \'id\': \'15dc03a3d27d4ed2800e64708c08eca1\'}'}], 'e': 'watchlist'}

    Set breakpoint
    sent: {'e':'set_break', 'p':{'line': 112, 'cond': null}}
    recv:


    Delete breakpoint
    sent: {'e': 'clear_break', 'p': {'line': 111}}
    recv:

    Set breakpoint with condition
    sent: {'e': 'set_break', 'p': {'line': 112, 'cond': 'ontext.foo == \'bar\''}}
    recv:

    Step into
    sent: {'e':'step'}
    recv: {'p': [{'expr': 'get_datetime().strftime(\'%Y-%m-%d %H:%M:%S\')#__QUANTOPIAN__', 'exc': null, 'value': '{\'truncated\': 0, \'context\': null, \'objtype\': \'str\', \'nodes\': [], \'data\': \'2016-01-04 15:30:00\', \'id\': \'2f0ef3930317424f8b4e73a9732242a4\'}'}], 'e': 'watchlist'}
    recv: {'p': {'index': 1, 'stack': [{'line': 111, 'code': ' security_weights = get_weights(context, data)', 'file': '<algorithm>', 'func': 'rebalance'}, {'line': 159, 'code': ' prices = data.history(context.security_list,', 'file': '<algorithm>', 'func': 'get_weights'}]}, 'e': 'stack'}

    Step out
    sent: {'e':'return'}
    sent: {'e':'step'}
    recv: {'p': [{'expr': 'get_datetime().strftime(\'%Y-%m-%d %H:%M:%S\')#__QUANTOPIAN__', 'exc': null, 'value': '{\'truncated\': 0, \'context\': null, \'objtype\': \'str\', \'nodes\': [], \'data\': \'2016-01-04 15:30:00\', \'id\': \'61725d03a6f44152be8febe02c31a70a\'}'}], 'e': 'watchlist'}
    recv: {'p': {'index': 1, 'stack': [{'line': 111, 'code': ' security_weights = get_weights(context, data)', 'file': '<algorithm>', 'func': 'rebalance'}, {'line': 163, 'code': ' security_weights = {}', 'file': '<algorithm>', 'func': 'get_weights'}]}, 'e': 'stack'}
    recv: {'p': [{'expr': 'get_datetime().strftime(\'%Y-%m-%d %H:%M:%S\')#__QUANTOPIAN__', 'exc': null, 'value': '{\'truncated\': 0, \'context\': null, \'objtype\': \'str\', \'nodes\': [], \'data\': \'2016-01-04 15:30:00\', \'id\': \'f047bc5ad9aa4b2a81eae95bab07ee75\'}'}], 'e': 'watchlist'}
    recv: {'p': {'index': 1, 'stack': [{'line': 111, 'code': ' security_weights = get_weights(context, data)', 'file': '<algorithm>', 'func': 'rebalance'}, {'line': 164, 'code': ' for security in context.security_list:', 'file': '<algorithm>', 'func': 'get_weights'}]}, 'e': 'stack'}

    Step over
    sent: {'e':'next'}
    recv: {'p': [{'expr': 'get_datetime().strftime(\'%Y-%m-%d %H:%M:%S\')#__QUANTOPIAN__', 'exc': null, 'value': '{\'truncated\': 0, \'context\': null, \'objtype\': \'str\', \'nodes\': [], \'data\': \'2016-01-04 15:30:00\', \'id\': \'06ede009f52c4ef9af484034104dbac7\'}'}], 'e': 'watchlist'}
    recv: {'p': {'index': 1, 'stack': [{'line': 111, 'code': ' security_weights = get_weights(context, data)', 'file': '<algorithm>', 'func': 'rebalance'}, {'line': 165, 'code': ' weights = np.array(weighting_fn(prices, security) for weighting_fn in context.history_weighting_fns)', 'file': '<algorithm>', 'func': 'get_weights'}]}, 'e': 'stack'}

    Continue
    sent: {'e':'continue'}
    recv: {'p': [{'expr': 'get_datetime().strftime(\'%Y-%m-%d %H:%M:%S\')#__QUANTOPIAN__', 'exc': null, 'value': '{\'truncated\': 0, \'context\': null, \'objtype\': \'str\', \'nodes\': [], \'data\': \'2016-01-04 00:00:00\', \'id\': \'b7d989ae20c04977b48089a1538ee9c7\'}'}], 'e': 'watchlist'}
    recv: {'p': {'index': 0, 'stack': [{'line': 42, 'code': '    context.pipelines = get_pipelines()', 'file': '<algorithm>', 'func': 'initialize'}]}, 'e': 'stack'}

    Finish
    sent: {'e':'disable','p':'soft'}
    recv: {'p': null, 'e': 'disable'}

    Set watch expr
    sent: {'e':'set_watch','p':['context']}
    recv: {'p': [{'expr': 'get_datetime().strftime(\'%Y-%m-%d %H:%M:%S\')#__QUANTOPIAN__', 'exc': null, 'value': '{\'truncated\': 0, \'context\': null, \'objtype\': \'str\', \'nodes\': [], \'data\': \'2016-01-04 00:00:00\', \'id\': \'0646a2fa3ff244439749a886273401b5\'}'}, {'expr': 'context', 'exc': null, 'value': '{\'truncated\': 0, \'context\': null, \'objtype\': \'AlgorithmContext\', \'nodes\': [\''portfolio'\', \''account'\'], \'data\': \'AlgorithmContext({'portfolio': Portfolio({'portfolio_value': 1000000.0, 'positions_exposure': 0.0, 'cash': 1000000.0, 'starting_cash': 1000000.0, 'returns': 0.0, 'capital_used': 0.0, 'pnl': 0.0, 'positions': {}, 'positions_value': 0.0, 'start_date': Timestamp('2016-01-04 00:00:00+0000', tz='UTC', offset='C')}), 'account': Account({'day_trades_remaining': inf, 'leverage': 0.0, 'regt_equity': 1000000.0, 'regt_margin': inf, 'available_funds': 1000000.0, 'maintenance_margin_requirement': 0.0, 'equity_with_loan': 1000000.0, 'buying_power': inf, 'initial_margin_requirement': 0.0, 'excess_liquidity': 1000000.0, 'settled_cash': 1000000.0, 'net_liquidation': 1000000.0, 'cushion': 1.0, 'total_positions_value': 0.0, 'net_leverage': 0.0, 'accrued_interest': 0.0, 'total_positions_exposure': 0.0})})\', \'id\': \'0bdea00673644178a54551fbbb45a5ad\'}'}], 'e': 'watchlist'}

    Eval
    sent: {'e':'eval','p':'context'}
    recv: {'p': {'input': 'context', 'exc': null, 'output': '{\'truncated\': 0, \'context\': null, \'objtype\': \'AlgorithmContext\', \'nodes\': [\''portfolio'\', \''account'\'], \'data\': \'AlgorithmContext({'portfolio': Portfolio({'portfolio_value': 1000000.0, 'positions_exposure': 0.0, 'cash': 1000000.0, 'starting_cash': 1000000.0, 'returns': 0.0, 'capital_used': 0.0, 'pnl': 0.0, 'positions': {}, 'positions_value': 0.0, 'start_date': Timestamp('2016-01-04 00:00:00+0000', tz='UTC', offset='C')}), 'account': Account({'day_trades_remaining': inf, 'leverage': 0.0, 'regt_equity': 1000000.0, 'regt_margin': inf, 'available_funds': 1000000.0, 'maintenance_margin_requirement': 0.0, 'equity_with_loan': 1000000.0, 'buying_power': inf, 'initial_margin_requirement': 0.0, 'excess_liquidity': 1000000.0, 'settled_cash': 1000000.0, 'net_liquidation': 1000000.0, 'cushion': 1.0, 'total_positions_value': 0.0, 'net_leverage': 0.0, 'accrued_interest': 0.0, 'total_positions_exposure': 0.0})})\', \'id\': \'197893af0ef94dfe9c0eea7e4b6a8c53\'}'}, 'e': 'print'}

    Expand watch expr tree by node index (Anything with nodes can be expanded)
    sent: {'e':'tree_expand','p':{'parent_id':'c7d0349fb76948ce8017a24d78d0ea4c','node':0}}
    recv: {'p': '{\'truncated\': 0, \'context\': {\'node\': 0, \'parent_id\': \'c7d0349fb76948ce8017a24d78d0ea4c\'}, \'objtype\': \'Portfolio\', \'nodes\': [\'capital_used\', \'cash\', \'pnl\', \'portfolio_value\', \'positions\', \'positions_exposure\', \'positions_value\', \'returns\', \'start_date\', \'starting_cash\'], \'data\': \'Portfolio({'portfolio_value': 1000000.0, 'positions_exposure': 0.0, 'cash': 1000000.0, 'starting_cash': 1000000.0, 'returns': 0.0, 'capital_used': 0.0, 'pnl': 0.0, 'positions': {}, 'positions_value': 0.0, 'start_date': Timestamp('2016-01-04 00:00:00+0000', tz='UTC', offset='C')})\', \'id\': \'510dd51c5f4f489b8432c29e2affe50f\'}', 'e': 'tree_node'}

    """
    pass


def get_backtest_results(backtest):
    with closing(websocket.create_connection(backtest['ws_url'])) as ws:
        ws.send(json.dumps({
            'e': 'open',
            'p': {
                'a': backtest['ws_open_msg'],
                'cursor': 0,
                'include_txn': False
            }
        }))
        while True:
            msg = json.loads(ws.recv())
            if msg['e'] == 'log':
                yield 'log', schema.validate(msg['p'], log_payload_schema(), raise_exc=True)

            elif msg['e'] == 'performance':
                yield 'performance', schema.validate(msg['p'], performance_payload_schema(), raise_exc=True)

            elif msg['e'] == 'risk_report':
                yield 'risk_report', schema.validate(msg['p'], risk_report_payload_schema(), raise_exc=True)

            elif msg['e'] == 'done':
                yield 'done', schema.validate(msg['p'], done_payload_schema(), raise_exc=True)
                ws.send('ACK')
                break

            elif msg['e'] == 'exception':
                exc = schema.validate(msg['p'], exception_payload_schema(), raise_exc=True)
                trace = '\n'.join("  File \"{}\", line {}, in {}\n    {}"
                                  "".format(s['filename'], s['lineno'], s['method'], s['line'])
                                  for s in exc['stack'])
                raise RuntimeError("Traceback (most recent call last):\n{}\n{}: {}"
                                   "".format(trace, exc['name'], exc['message']))
            else:
                raise QuantopianException("unknown backtest event '{}'".format(msg['e']))


def get_backtest_logs(backtest, start=0, end=200):
    url = build_url('backtests', 'log_entries', backtest_id=backtest['id'], start=start, end=end)
    headers = {
        'x-csrf-token': session.browser.get_csrf_token(build_url('algorithms')),
        'x-requested-with': 'XMLHttpRequest'
    }
    response = session.browser.get(url, headers=headers)
    if not response.ok:
        raise RequestError('failed to get backtest logs', response)

    valid, data_or_errors = schema.validate(response.json(), {
        'status': schema.string(required=True, nullable=False),
        'data': schema.dictionary(
            required=True,
            nullable=True,
            schema={
                'id': schema.string(required=True, nullable=False, allowed=[backtest['id']]),
                'log_count': schema.integer(required=True, nullable=False, min=-1),
                'min_avail': schema.integer(required=True, nullable=True, min=-1),
                'max_avail': schema.integer(required=True, nullable=True, min=-1),
                'logs': schema.list_(
                    required=True,
                    nullable=False,
                    schema=schema.dictionary(
                        schema={
                            'a': schema.datetime_(required=True, nullable=False, min=0, rename='trading_timestamp',
                                                  coerce='millis_timestamp'),
                            'c': schema.string(required=True, nullable=True, strip=True, rename='log_class'),
                            'f': schema.string(required=True, nullable=True, empty=False, rename='method'),
                            'i': schema.integer(required=True, nullable=True, min=1, rename='line'),
                            'l': schema.string(required=True, nullable=False, coerce=_log_level, rename='level'),
                            'm': schema.string(required=True, nullable=False, empty=True, rename='message'),
                            'o': schema.integer(required=True, nullable=False, min=1, rename='count'),
                            'r': schema.boolean(required=True, nullable=True, rename='truncated'),
                            't': schema.datetime_(required=True, nullable=False, min=0, rename='log_timestamp',
                                                  coerce='millis_timestamp'),
                        }
                    )
                )
            }
        )
    }, allow_unknown=True)
    if not valid:
        raise ResponseValidationError('GET', url, None, data_or_errors)

    data_or_errors['data']['logs'].sort(key=lambda log: log['count'])
    return data_or_errors['data']


def cancel_backtest(backtest, algorithm):
    url = build_url('backtests', backtest['id'], 'cancel_backtest')
    headers = {
        'x-csrf-token': session.browser.get_csrf_token(build_url('algorithms', algorithm['id'])),
        'x-requested-with': 'XMLHttpRequest'
    }
    data = {
        'algo_id': algorithm['id'],
        'backtest_id': backtest['id']
    }
    response = session.browser.post(url, data=data, headers=headers)
    if not response.ok:
        raise RequestError('failed to cancel backtest', response)

    valid, data_or_errors = schema.validate(response.json(), {
        'status': schema.string(required=True, nullable=False)
    }, allow_unknown=True)
    if not valid:
        raise ResponseValidationError('POST', url, data, data_or_errors)

    return data_or_errors['status'].lower() == 'ok'
