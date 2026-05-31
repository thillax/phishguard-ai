import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Load dataset
df = pd.read_csv('../data/phishing.csv')

# Features and target
X = df.drop(columns=['Index', 'class'])
y = df['class']

# Train/Test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42)

# Train model
print("Training model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(f"\n✅ Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
print("\nReport:")
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, '../model/phishing_model.pkl')
joblib.dump(list(X.columns), '../model/feature_names.pkl')
print("\n✅ Model saved!")