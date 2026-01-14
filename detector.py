import argparse
import sys

def run_beelzebub(target):
    # import ONLY when needed
    from beelzebub_detector import main as beelzebub_main
    beelzebub_main(target)

def run_cowrie(target):
    from cowrie_detector import main as cowrie_main
    # Just call the main function from cowrie_detector.py
    cowrie_main(target)


def run_dionaea(target):
    from dionaea_detector import main as dionaea_main
    dionaea_main(target)
    
def run_snare(target):
    from snare_detector import main as snare_main
    snare_main(target)   # default port 80



DETECTORS = {
    "beelzebub": run_beelzebub,
    "cowrie": run_cowrie,
    "dionaea": run_dionaea,
    "snare": run_snare,
}

def main():
    parser = argparse.ArgumentParser(
        description="Simple Honeypot Detector Launcher"
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument(
        "honeypot",
        choices=DETECTORS.keys(),
        help="Honeypot detector to run"
    )

    args = parser.parse_args()

    DETECTORS[args.honeypot](args.target)

if __name__ == "__main__":
    main()

