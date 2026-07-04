import logging as _logging
_LOGGER = None
def get_logger():
    global _LOGGER
    if not _LOGGER:
        _LOGGER = _logging.getLogger('symtuner')
        if not _logging.getLogger().handlers:
            formatter = _logging.Formatter(fmt='%(asctime)s symtuner [%(levelname)s] %(message)s',
                                           datefmt='%Y-%m-%d %H:%M:%S')
            stderr_handler = _logging.StreamHandler()
            stderr_handler.setFormatter(formatter)
            _LOGGER.addHandler(stderr_handler)
            _LOGGER.setLevel('INFO')
    return _LOGGER