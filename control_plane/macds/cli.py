import argparse
from macds.main import main as run_main

def main():
    parser = argparse.ArgumentParser(
        description="MACDS Control Plane"
    )
    parser.add_argument(
        "--mode",
        choices=["run", "test"],
        default="run",
        help="Execution mode"
    )

    args = parser.parse_args()

    if args.mode == "run":
        run_main()
    elif args.mode == "test":
        print("Running test environment...")
        from macds.test_environment import main as test_main
        test_main()

if __name__ == "__main__":
    main()
