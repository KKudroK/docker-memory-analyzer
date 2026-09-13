"""Run Volatility using the Python environment chosen by the caller."""
import multiprocessing


if __name__ == '__main__':
    # Windows의 자식 프로세스 시작을 준비한 뒤 현재 Python 환경의 공식 CLI로 진입한다.
    multiprocessing.freeze_support()
    from volatility3.cli import main
    main()
