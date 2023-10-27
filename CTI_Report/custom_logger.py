import logging


def my_logger(name: str) -> logging.Logger:
    """
    ### Create Logger

    Args:
        - `name`: logger user name

    Returns:
        - `logging.Logger`: logger to be used
    """
    logger: logging.Logger = logging.getLogger(name=name)
    file_handler = logging.FileHandler(f"log.txt")
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)
    return logger
