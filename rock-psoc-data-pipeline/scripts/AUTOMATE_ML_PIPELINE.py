"""
Master ML Pipeline Automation Script
Runs the complete Phase 6 ML improvement pipeline with minimal user interaction

Usage:
    python scripts/AUTOMATE_ML_PIPELINE.py [options]

Options:
    --full          Run complete pipeline (download + train + deploy)
    --download      Only download datasets
    --train         Only train models (requires datasets)
    --deploy        Only deploy models (requires trained v2 models)
    --skip-cicids   Skip CICIDS2017 (requires manual download)
    --quick         Use 50% of CICIDS2017 data (faster training)
"""

import sys
import subprocess
import time
from pathlib import Path
from datetime import datetime
import argparse

# Setup paths
BASE_DIR = Path(__file__).parent.parent
SCRIPTS_DIR = BASE_DIR / 'scripts'

# Color output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 70}")
    print(f"{text}")
    print(f"{'=' * 70}{Colors.END}\n")

def print_step(step_num, total_steps, text):
    print(f"{Colors.CYAN}[{step_num}/{total_steps}] {text}{Colors.END}")

def print_success(text):
    print(f"{Colors.GREEN}✅ {text}{Colors.END}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}❌ {text}{Colors.END}")

def run_script(script_name, description):
    """Run a Python script and handle errors"""
    script_path = SCRIPTS_DIR / script_name
    
    if not script_path.exists():
        print_error(f"Script not found: {script_name}")
        return False
    
    print(f"\n{Colors.BLUE}Running: {description}{Colors.END}")
    print(f"Script: {script_name}")
    
    try:
        start_time = time.time()
        
        # Run script
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(BASE_DIR),
            capture_output=False,
            text=True,
            check=False
        )
        
        elapsed = time.time() - start_time
        
        if result.returncode == 0:
            print_success(f"Completed in {elapsed:.1f} seconds")
            return True
        else:
            print_error(f"Failed with exit code {result.returncode}")
            return False
            
    except KeyboardInterrupt:
        print_warning("\nScript interrupted by user")
        return False
    except Exception as e:
        print_error(f"Error: {e}")
        return False

def check_prerequisites():
    """Check if required directories and files exist"""
    print_header("🔍 CHECKING PREREQUISITES")
    
    # Check directories
    required_dirs = [
        BASE_DIR / 'data',
        BASE_DIR / 'models',
        BASE_DIR / 'scripts',
    ]
    
    for dir_path in required_dirs:
        if dir_path.exists():
            print_success(f"Directory exists: {dir_path.name}")
        else:
            print_warning(f"Creating directory: {dir_path.name}")
            dir_path.mkdir(parents=True, exist_ok=True)
    
    # Check Python packages
    print("\n📦 Checking Python packages...")
    required_packages = [
        'pandas', 'numpy', 'scikit-learn', 
        'matplotlib', 'seaborn', 'requests'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
            print_success(f"Package installed: {package}")
        except ImportError:
            print_warning(f"Package missing: {package}")
            missing_packages.append(package)
    
    if missing_packages:
        print_warning(f"\nMissing packages: {', '.join(missing_packages)}")
        print("Install with: pip install " + " ".join(missing_packages) + " --break-system-packages")
        response = input("\nContinue anyway? (y/n): ")
        if response.lower() != 'y':
            return False
    
    return True

def download_datasets(skip_cicids=False):
    """Phase 1: Download all datasets"""
    print_header("📥 PHASE 1: DOWNLOADING DATASETS")
    
    total_steps = 2 if skip_cicids else 3
    current_step = 0
    
    # CISA KEV (automatic)
    current_step += 1
    print_step(current_step, total_steps, "Downloading CISA KEV (automatic)")
    if not run_script('12_download_cisa_kev_latest.py', 'CISA Known Exploited Vulnerabilities'):
        print_warning("CISA KEV download failed, but continuing...")
    
    # PhishTank (automatic)
    current_step += 1
    print_step(current_step, total_steps, "Downloading PhishTank (automatic)")
    if not run_script('13_download_phishtank_latest.py', 'PhishTank Phishing URLs'):
        print_warning("PhishTank download failed, but continuing...")
    
    # UNSW-NB15 (fully automatic from Kaggle!)
    if not skip_cicids:
        current_step += 1
        print_step(current_step, total_steps, "Downloading UNSW-NB15 from Kaggle (automatic)")
        print("This dataset is a modern alternative to CICIDS2017")
        print("Advantages:")
        print("   ✅ Fully automatic (no manual download)")
        print("   ✅ Smaller size (700 MB vs 1.2 GB)")
        print("   ✅ Faster download")
        print("   ✅ Modern attacks (2015)")
        
        if not run_script('9_download_unsw_nb15.py', 'UNSW-NB15 Download and Processing'):
            print_error("UNSW-NB15 download failed!")
            print_warning("You can try CICIDS2017 instead:")
            print("   python scripts/9_download_cicids2017.py")
            return False
    
    print_success("Dataset download phase complete!")
    return True

def train_models(quick_mode=False):
    """Phase 2: Train all models"""
    print_header("🤖 PHASE 2: TRAINING MODELS")
    
    # Check if datasets exist
    processed_dir = BASE_DIR / 'data' / 'processed'
    
    # Intrusion model
    print_step(1, 1, "Training Intrusion Detection Model v2")
    
    unsw_file = processed_dir / 'unsw_nb15_processed.csv'
    cicids_file = processed_dir / 'cicids2017_processed.csv'
    
    if unsw_file.exists():
        print(f"Found UNSW-NB15 dataset: {unsw_file.stat().st_size / (1024*1024):.1f} MB")
        if quick_mode:
            print_warning("Quick mode: Will use 50% of data")
        
        if not run_script('10_retrain_intrusion_model.py', 'Intrusion Detection Training'):
            print_error("Model training failed!")
            return False
    elif cicids_file.exists():
        print(f"Found CICIDS2017 dataset: {cicids_file.stat().st_size / (1024*1024):.1f} MB")
        if quick_mode:
            print_warning("Quick mode: Will use 50% of data")
        
        if not run_script('10_retrain_intrusion_model.py', 'Intrusion Detection Training'):
            print_error("Model training failed!")
            return False
    else:
        print_warning("No modern dataset found - skipping intrusion model retraining")
        print("Will continue using existing NSL-KDD model")
    
    print_success("Model training phase complete!")
    return True

def deploy_models():
    """Phase 3: Deploy trained models"""
    print_header("🚀 PHASE 3: DEPLOYING MODELS")
    
    # Check if v2 models exist
    model_dir = BASE_DIR / 'models' / 'saved_models'
    v2_model = model_dir / 'intrusion_model_v2.pkl'
    
    if not v2_model.exists():
        print_warning("No v2 models found to deploy")
        print("Skipping deployment phase")
        return True
    
    print_step(1, 1, "Updating API to use v2 models")
    if not run_script('11_update_api_models.py', 'Model Deployment'):
        print_error("Model deployment failed!")
        return False
    
    print_success("Model deployment phase complete!")
    return True

def generate_report():
    """Generate summary report"""
    print_header("📊 PIPELINE EXECUTION REPORT")
    
    # Check what was created
    processed_dir = BASE_DIR / 'data' / 'processed'
    model_dir = BASE_DIR / 'models' / 'saved_models'
    eval_dir = BASE_DIR / 'models' / 'evaluation'
    
    print(f"\n{Colors.BOLD}Datasets:{Colors.END}")
    
    datasets = {
        'UNSW-NB15': processed_dir / 'unsw_nb15_processed.csv',
        'CICIDS2017': processed_dir / 'cicids2017_processed.csv',
        'CISA KEV': processed_dir / 'cisa_kev_latest.csv',
        'PhishTank': processed_dir / 'phishtank_latest.csv',
    }
    
    for name, path in datasets.items():
        if path.exists():
            size_mb = path.stat().st_size / (1024*1024)
            print_success(f"{name}: {size_mb:.1f} MB")
        else:
            print_warning(f"{name}: Not found")
    
    print(f"\n{Colors.BOLD}Models:{Colors.END}")
    
    models = {
        'Intrusion v2': model_dir / 'intrusion_model_v2.pkl',
        'Intrusion (active)': model_dir / 'intrusion_model.pkl',
    }
    
    for name, path in models.items():
        if path.exists():
            size_mb = path.stat().st_size / (1024*1024)
            print_success(f"{name}: {size_mb:.1f} MB")
        else:
            print_warning(f"{name}: Not found")
    
    print(f"\n{Colors.BOLD}Evaluation:{Colors.END}")
    
    eval_files = {
        'Confusion Matrix': eval_dir / 'intrusion_v2_confusion_matrix.png',
        'Feature Importance': eval_dir / 'intrusion_v2_feature_importance.csv',
    }
    
    for name, path in eval_files.items():
        if path.exists():
            print_success(f"{name}: Available")
        else:
            print_warning(f"{name}: Not generated")
    
    print(f"\n{Colors.BOLD}Next Steps:{Colors.END}")
    print("1. Restart prediction API:")
    print("   python scripts/6_create_prediction_api.py")
    print("\n2. Test in React app:")
    print("   Go to Predictions → Run Intrusion Detection")
    print("\n3. Compare with old model:")
    print("   Check accuracy metrics in models/evaluation/")

def main():
    parser = argparse.ArgumentParser(
        description='Automated ML Pipeline for Phase 6',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/AUTOMATE_ML_PIPELINE.py --full
      Run complete pipeline (download + train + deploy)
  
  python scripts/AUTOMATE_ML_PIPELINE.py --download
      Only download datasets
  
  python scripts/AUTOMATE_ML_PIPELINE.py --train --quick
      Train with 50% of data (faster)
  
  python scripts/AUTOMATE_ML_PIPELINE.py --skip-cicids
      Skip CICIDS2017 manual download
        """
    )
    
    parser.add_argument('--full', action='store_true',
                       help='Run complete pipeline')
    parser.add_argument('--download', action='store_true',
                       help='Only download datasets')
    parser.add_argument('--train', action='store_true',
                       help='Only train models')
    parser.add_argument('--deploy', action='store_true',
                       help='Only deploy models')
    parser.add_argument('--skip-cicids', action='store_true',
                       help='Skip CICIDS2017 (use existing NSL-KDD)')
    parser.add_argument('--quick', action='store_true',
                       help='Quick mode (50% data, faster training)')
    
    args = parser.parse_args()
    
    # Default to full if no options specified
    if not any([args.full, args.download, args.train, args.deploy]):
        args.full = True
    
    print_header("🤖 AUTOMATED ML PIPELINE - PHASE 6")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check prerequisites
    if not check_prerequisites():
        print_error("Prerequisites check failed!")
        sys.exit(1)
    
    start_time = time.time()
    success = True
    
    try:
        # Execute pipeline phases
        if args.full or args.download:
            if not download_datasets(skip_cicids=args.skip_cicids):
                success = False
                print_error("Download phase failed!")
                sys.exit(1)
        
        if args.full or args.train:
            if not train_models(quick_mode=args.quick):
                success = False
                print_error("Training phase failed!")
                sys.exit(1)
        
        if args.full or args.deploy:
            if not deploy_models():
                success = False
                print_error("Deployment phase failed!")
                sys.exit(1)
        
    except KeyboardInterrupt:
        print_warning("\n\nPipeline interrupted by user")
        success = False
    except Exception as e:
        print_error(f"\nUnexpected error: {e}")
        success = False
    
    # Final report
    total_time = time.time() - start_time
    
    generate_report()
    
    print_header("🏁 PIPELINE COMPLETE")
    print(f"Total time: {total_time / 60:.1f} minutes")
    print(f"Status: {'✅ SUCCESS' if success else '❌ FAILED'}")
    
    if success:
        print(f"\n{Colors.GREEN}{Colors.BOLD}🎉 All done! Your ML models are now improved!{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}⚠️  Pipeline completed with errors. Check logs above.{Colors.END}")

if __name__ == '__main__':
    main()