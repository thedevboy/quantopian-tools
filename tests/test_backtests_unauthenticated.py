# -*- coding: utf-8 -*-
from __future__ import print_function, absolute_import, division, unicode_literals

import datetime

from quantopian_tools import algorithms, backtests


# def test_run_backtest(unauthenticated_browser, sample_mean_reversion_alg_code):
#     title = 'Backtest Test ({})'.format(datetime.datetime.now().isoformat())
#     algorithm_id = algorithms.new_algorithm(title)
#     algorithm = algorithms.get_algorithm(algorithm_id)
#     algorithm['code'] = sample_mean_reversion_alg_code
#     assert algorithms.save_algorithm(algorithm)
#
#     results = list(backtests.run_backtest(algorithm,
#                                           start_date=datetime.date(2016, 1, 1),
#                                           end_date=datetime.date(2016, 2, 1),
#                                           capital_base=1000000, data_frequency='minute'))
#     assert algorithms.delete_algorithm(algorithm)
#     print(results)


def test_start_backtest_get_logs(unauthenticated_browser, sample_logging_alg_code):
    title = 'Backtest Test ({})'.format(datetime.datetime.now().isoformat())
    algorithm_id = algorithms.new_algorithm(title)
    algorithm = algorithms.get_algorithm(algorithm_id)
    algorithm['code'] = sample_logging_alg_code
    assert algorithms.save_algorithm(algorithm)
    try:
        backtest = backtests.start_backtest(algorithm,
                                            start_date=datetime.date(2016, 1, 1),
                                            end_date=datetime.date(2016, 1, 2),
                                            capital_base=1000000, data_frequency='minute')
        logs = []
        start = 0
        available = 0
        for result_type, result in backtests.get_backtest_results(backtest):
            if result_type != 'log':
                continue
            available += result['num_lines']
            while available > 0:
                chunk = min(available, 200)
                end = start + chunk
                available -= chunk
                logs.extend(backtests.get_backtest_logs(backtest, start=start, end=end)['logs'])
                start += chunk
        for log in logs:
            assert 'log_timestamp' in log and isinstance(log.pop('log_timestamp'), datetime.datetime)
        assert logs == [
            {
                'count': 1,
                'level': 'ERROR',
                'line': 2,
                'log_class': 'AlgoLog',
                # 'log_timestamp': datetime.datetime(2017, 2, 26, 12, 4, 47, 474000),
                'message': 'error',
                'method': 'initialize',
                'trading_timestamp': datetime.datetime(1969, 12, 31, 16, 0),
                'truncated': False,
            },
            {
                'count': 2,
                'level': 'WARNING',
                'line': 3, 'method': 'initialize',
                'log_class': 'AlgoLog',
                # 'log_timestamp': datetime.datetime(2017, 2, 26, 12, 4, 47, 474000),
                'message': 'warn',
                'trading_timestamp': datetime.datetime(1969, 12, 31, 16, 0),
                'truncated': False,
            },
            {
                'count': 3,
                'level': 'DEBUG',
                'line': 4,
                'log_class': 'AlgoLog',
                # 'log_timestamp': datetime.datetime(2017, 2, 26, 12, 4, 47, 475000),
                'message': 'debug',
                'method': 'initialize',
                'trading_timestamp': datetime.datetime(1969, 12, 31, 16, 0),
                'truncated': False,
            },
            {
                'count': 4,
                'level': 'INFO',
                'line': 5,
                'log_class': 'AlgoLog',
                # 'log_timestamp': datetime.datetime(2017, 2, 26, 12, 4, 47, 475000),
                'message': 'info',
                'method': 'initialize',
                'trading_timestamp': datetime.datetime(1969, 12, 31, 16, 0),
                'truncated': False,
            },
            {
                'count': 5,
                'level': 'INFO',
                'line': 207,
                'log_class': 'Print',
                # 'log_timestamp': datetime.datetime(2017, 2, 26, 12, 4, 47, 475000),
                'message': 'print',
                'method': 'write',
                'trading_timestamp': datetime.datetime(1969, 12, 31, 16, 0),
                'truncated': False,
            },
        ]
    finally:
        assert algorithms.delete_algorithm(algorithm)


# def test_start_and_cancel_backtest(unauthenticated_browser, sample_mean_reversion_alg_code):
#     title = 'Backtest Test ({})'.format(datetime.datetime.now().isoformat())
#     algorithm_id = algorithms.new_algorithm(title)
#     algorithm = algorithms.get_algorithm(algorithm_id)
#     algorithm['code'] = sample_mean_reversion_alg_code
#     assert algorithms.save_algorithm(algorithm)
#     try:
#         backtest = backtests.start_backtest(algorithm,
#                                             start_date=datetime.date(2016, 1, 1),
#                                             end_date=datetime.date(2016, 2, 1),
#                                             capital_base=1000000, data_frequency='minute')
#         assert backtests.cancel_backtest(backtest, algorithm)
#     finally:
#         assert algorithms.delete_algorithm(algorithm)
