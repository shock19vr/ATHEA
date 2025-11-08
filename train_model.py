"""
Training Script for Anomaly Detection Model
Run this script to train the model with your labeled data.
"""

import argparse
import sys
from pathlib import Path
from training_data_manager import TrainingDataManager
from supervised_model import SupervisedAnomalyDetector


def create_sample_data():
    """Create sample training dataset"""
    print("Creating sample training dataset...")
    manager = TrainingDataManager()
    dataset_path = manager.create_sample_dataset()
    print(f"✅ Sample dataset created at: {dataset_path}")
    
    stats = manager.get_statistics("sample_anomalies")
    print(f"\nDataset Statistics:")
    print(f"  Total Samples: {stats['total_samples']}")
    print(f"  Labels: {stats['label_distribution']}")
    print(f"  Attack Types: {stats['attack_type_distribution']}")


def list_datasets():
    """List all available training datasets"""
    manager = TrainingDataManager()
    datasets = manager.list_datasets()
    
    if not datasets:
        print("No training datasets found.")
        print("Run: python train_model.py --create-sample")
        return
    
    print("\n📊 Available Training Datasets:\n")
    for ds in datasets:
        print(f"  📁 {ds['name']}")
        print(f"     Samples: {ds['samples']}")
        print(f"     Created: {ds['created_at']}")
        print(f"     Description: {ds['description']}")
        print()


def train_model(dataset_name: str, model_type: str, output_path: str):
    """Train model on specified dataset"""
    print(f"\n🚀 Training {model_type} model on dataset: {dataset_name}\n")
    
    # Create models directory if it doesn't exist
    Path("models").mkdir(exist_ok=True)
    
    # Initialize detector
    detector = SupervisedAnomalyDetector(model_type=model_type)
    
    try:
        # Train
        metrics = detector.train_from_dataset(dataset_name, test_size=0.2, validate=True)
        
        print("\n" + "="*60)
        print("🎯 TRAINING RESULTS")
        print("="*60)
        
        # Binary classification results
        binary = metrics['binary_metrics']
        print(f"\n📊 Binary Classification (Anomaly vs Normal):")
        print(f"  Accuracy: {binary['accuracy']:.3f}")
        print(f"  F1 Score: {binary['f1_score']:.3f}")
        
        # Attack type classification results
        if metrics['attack_type_metrics']:
            attack = metrics['attack_type_metrics']
            print(f"\n🎯 Attack Type Classification:")
            print(f"  Accuracy: {attack['accuracy']:.3f}")
            print(f"  F1 Score: {attack['f1_score']:.3f}")
        
        # Cross-validation
        if metrics['cv_scores']:
            cv = metrics['cv_scores']
            print(f"\n✅ Cross-Validation:")
            print(f"  CV F1 Score: {cv['binary_cv_mean']:.3f} (+/- {cv['binary_cv_std']:.3f})")
        
        # Feature importance
        print(f"\n🔍 Top 10 Most Important Features:")
        top_features = detector.get_top_features(10)
        for i, (feature, importance) in enumerate(top_features, 1):
            print(f"  {i:2d}. {feature:30s} {importance:.4f}")
        
        # Save model
        detector.save_model(output_path)
        print(f"\n💾 Model saved to: {output_path}")
        
        print("\n" + "="*60)
        print("✅ TRAINING COMPLETE!")
        print("="*60)
        
        return True
        
    except FileNotFoundError:
        print(f"❌ Error: Dataset '{dataset_name}' not found.")
        print("Available datasets:")
        list_datasets()
        return False
        
    except Exception as e:
        print(f"❌ Error during training: {e}")
        import traceback
        traceback.print_exc()
        return False


def add_sample_interactive():
    """Interactive mode to add training samples"""
    print("\n📝 Add Training Sample (Interactive Mode)\n")
    
    manager = TrainingDataManager()
    
    # Get dataset name
    dataset_name = input("Dataset name: ").strip()
    if not dataset_name:
        print("❌ Dataset name required")
        return
    
    # Check if dataset exists, create if not
    datasets = manager.list_datasets()
    if not any(ds['name'] == dataset_name for ds in datasets):
        print(f"Dataset '{dataset_name}' doesn't exist. Creating...")
        desc = input("Description (optional): ").strip()
        manager.create_training_dataset(dataset_name, desc)
    
    # Get sample details
    print("\nEnter sample details:")
    
    try:
        event_id = int(input("EventID (e.g., 4625): "))
        level = int(input("Level (1-5, where 1=Critical): "))
        channel = input("Channel (Security/System/Application): ").strip()
        computer = input("Computer name: ").strip()
        hour = int(input("Hour (0-23): "))
        raw_log = input("Raw log text: ").strip()
        
        label = input("Label (anomaly/normal): ").strip().lower()
        if label not in ['anomaly', 'normal']:
            print("❌ Label must be 'anomaly' or 'normal'")
            return
        
        if label == 'anomaly':
            print("\nAttack types: brute_force, powershell_exploit, suspicious_process,")
            print("              lateral_movement, privilege_escalation, defense_evasion,")
            print("              persistence, credential_theft, data_exfiltration, etc.")
            attack_type = input("Attack type: ").strip()
            severity = input("Severity (low/medium/high/critical): ").strip()
        else:
            attack_type = 'normal'
            severity = 'low'
        
        notes = input("Notes (optional): ").strip()
        
        # Build event data
        event_data = {
            'EventID': event_id,
            'Level': level,
            'Channel': channel,
            'Computer': computer,
            'Hour': hour,
            'IsNightTime': 1 if hour < 6 or hour > 22 else 0,
            'IsBusinessHours': 1 if 9 <= hour <= 17 else 0,
            'RawLog': raw_log
        }
        
        # Add sample
        manager.add_training_sample(
            dataset_name=dataset_name,
            event_data=event_data,
            label=label,
            attack_type=attack_type,
            severity=severity,
            notes=notes
        )
        
        print(f"\n✅ Sample added to dataset '{dataset_name}'")
        
        # Show stats
        stats = manager.get_statistics(dataset_name)
        print(f"Total samples in dataset: {stats['total_samples']}")
        
    except ValueError as e:
        print(f"❌ Invalid input: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Train anomaly detection model with labeled data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create sample dataset
  python train_model.py --create-sample
  
  # List available datasets
  python train_model.py --list
  
  # Train model
  python train_model.py --train sample_anomalies
  
  # Train with specific model type
  python train_model.py --train my_data --model-type gradient_boosting
  
  # Add sample interactively
  python train_model.py --add-sample
        """
    )
    
    parser.add_argument('--create-sample', action='store_true',
                       help='Create sample training dataset')
    parser.add_argument('--list', action='store_true',
                       help='List available training datasets')
    parser.add_argument('--train', type=str, metavar='DATASET',
                       help='Train model on specified dataset')
    parser.add_argument('--model-type', type=str, default='random_forest',
                       choices=['random_forest', 'gradient_boosting'],
                       help='Model type to use (default: random_forest)')
    parser.add_argument('--output', type=str, default='models/trained_model.pkl',
                       help='Output path for trained model (default: models/trained_model.pkl)')
    parser.add_argument('--add-sample', action='store_true',
                       help='Add training sample interactively')
    
    args = parser.parse_args()
    
    # Show help if no arguments
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    # Execute commands
    if args.create_sample:
        create_sample_data()
    
    if args.list:
        list_datasets()
    
    if args.add_sample:
        add_sample_interactive()
    
    if args.train:
        success = train_model(args.train, args.model_type, args.output)
        if not success:
            sys.exit(1)


if __name__ == "__main__":
    main()
