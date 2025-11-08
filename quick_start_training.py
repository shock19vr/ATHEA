"""
Quick Start Training Script
Get started with ML model training in 3 simple steps.
"""

import sys
from pathlib import Path
from training_data_manager import TrainingDataManager
from supervised_model import SupervisedAnomalyDetector


def main():
    print("=" * 70)
    print("🎓 ANOMALY DETECTION MODEL - QUICK START TRAINING")
    print("=" * 70)
    print()
    
    # Step 1: Create sample dataset
    print("📦 Step 1: Creating sample training dataset...")
    print("-" * 70)
    
    manager = TrainingDataManager()
    
    # Check if sample already exists
    datasets = manager.list_datasets()
    if any(ds['name'] == 'sample_anomalies' for ds in datasets):
        print("✅ Sample dataset already exists")
    else:
        manager.create_sample_dataset()
    
    # Show stats
    stats = manager.get_statistics('sample_anomalies')
    print(f"\n📊 Dataset: sample_anomalies")
    print(f"   Total Samples: {stats['total_samples']}")
    print(f"   Anomalies: {stats['label_distribution'].get('anomaly', 0)}")
    print(f"   Normal: {stats['label_distribution'].get('normal', 0)}")
    print(f"   Attack Types: {len(stats['attack_type_distribution'])}")
    
    input("\n✅ Press Enter to continue to training...")
    
    # Step 2: Train the model
    print("\n🚀 Step 2: Training the model...")
    print("-" * 70)
    
    # Create models directory
    Path("models").mkdir(exist_ok=True)
    
    detector = SupervisedAnomalyDetector(model_type='random_forest')
    
    try:
        print("Training Random Forest classifier...")
        print("This may take 10-30 seconds...\n")
        
        metrics = detector.train_from_dataset('sample_anomalies', test_size=0.2)
        
        print("\n" + "=" * 70)
        print("🎯 TRAINING RESULTS")
        print("=" * 70)
        
        # Binary classification
        binary = metrics['binary_metrics']
        print(f"\n📊 Anomaly Detection Performance:")
        print(f"   Accuracy:  {binary['accuracy']:.1%}")
        print(f"   F1 Score:  {binary['f1_score']:.1%}")
        
        # Attack type classification
        if metrics['attack_type_metrics']:
            attack = metrics['attack_type_metrics']
            print(f"\n🎯 Attack Type Classification:")
            print(f"   Accuracy:  {attack['accuracy']:.1%}")
            print(f"   F1 Score:  {attack['f1_score']:.1%}")
        
        # Cross-validation
        if metrics['cv_scores']:
            cv = metrics['cv_scores']
            print(f"\n✅ Cross-Validation:")
            print(f"   CV Score:  {cv['binary_cv_mean']:.1%} (+/- {cv['binary_cv_std']:.1%})")
        
        # Top features
        print(f"\n🔍 Top 5 Most Important Features:")
        top_features = detector.get_top_features(5)
        for i, (feature, importance) in enumerate(top_features, 1):
            bar = "█" * int(importance * 50)
            print(f"   {i}. {feature:25s} {bar} {importance:.3f}")
        
        # Save model
        model_path = "models/quick_start_model.pkl"
        detector.save_model(model_path)
        print(f"\n💾 Model saved to: {model_path}")
        
        input("\n✅ Press Enter to continue to next steps...")
        
        # Step 3: Next steps
        print("\n📚 Step 3: What's Next?")
        print("-" * 70)
        print()
        print("✅ You've successfully trained your first model!")
        print()
        print("🎯 Next Steps:")
        print()
        print("1️⃣  Add Your Own Data:")
        print("   python train_model.py --add-sample")
        print()
        print("2️⃣  Create CSV Template:")
        print("   python create_training_template.py")
        print("   (Then edit the CSV and import it)")
        print()
        print("3️⃣  Retrain with Your Data:")
        print("   python train_model.py --train your_dataset_name")
        print()
        print("4️⃣  View All Datasets:")
        print("   python train_model.py --list")
        print()
        print("5️⃣  Read Full Documentation:")
        print("   See TRAINING_README.md and TRAINING_GUIDE.md")
        print()
        print("=" * 70)
        print("🎉 TRAINING COMPLETE!")
        print("=" * 70)
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error during training: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    try:
        success = main()
        if not success:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Training interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
