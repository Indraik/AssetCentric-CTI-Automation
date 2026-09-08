from threat_intelligence.collector_manager import run_pipeline
from utils.logger import setup_logger


logger = setup_logger()


def main():

    logger.info("Test Runner | Starting Threat Intelligence Pipeline")

    try:

        run_pipeline()

    except Exception as e:

        logger.error(f"Test Runner | Pipeline failed | {str(e)}")

    finally:

        logger.info("Test Runner | Pipeline execution finished")


if __name__ == "__main__":
    main()