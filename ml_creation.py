from tensorflow import keras
from sklearn.preprocessing import StandardScaler
import numpy as np
import tensorflow as tf
import pandas as pd
import plotly.graph_objects as go
import matplotlib.pyplot as plt
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM, Dropout, RepeatVector, TimeDistributed
import json
from keras.models import load_model

pd.set_option('display.max_rows', None)
arr = [38,38,38,38,38,0,21,9,0,7]

arr2 = []
for i in range(len(arr)):
    arr2.append(i)
numm = int(len(arr)*0.20)
df = pd.DataFrame(list(zip(arr2,arr)), columns = ["Day","Frequency"])
train = df.loc[df['Day'] <= numm]
test = df.loc[df['Day'] > -1]
print(train.shape, test.shape)
scaler = StandardScaler()
scaler = scaler.fit(np.array(train['Frequency']).reshape(-1,1))

train['Frequency'] = scaler.transform(np.array(train['Frequency']).reshape(-1,1))
test['Frequency'] = scaler.transform(np.array(test['Frequency']).reshape(-1,1))

TIME_STEPS=1

def create_sequences(X, y, time_steps=TIME_STEPS):
    X_out, y_out = [], []
    for i in range(len(X)):
        X_out.append(X.iloc[i:(i+1)].values)
        y_out.append(y.iloc[i])
    
    return np.array(X_out), np.array(y_out)


X_train, y_train = create_sequences(train[['Frequency']], train['Frequency'])
X_test, y_test = create_sequences(test[['Frequency']], test['Frequency'])
print("Training input shape: ", X_train.shape)
print("Testing input shape: ", X_test.shape)

X_train[numm-1]
np.random.seed(21)
tf.random.set_seed(21)

model = Sequential()
model.add(LSTM(128, activation = 'tanh', input_shape=(X_train.shape[1], X_train.shape[2])))
model.add(Dropout(rate=0.2))
model.add(RepeatVector(X_train.shape[1]))
model.add(LSTM(128, activation = 'tanh', return_sequences=True))
model.add(Dropout(rate=0.2))
model.add(TimeDistributed(Dense(X_train.shape[2])))
model.compile(optimizer=keras.optimizers.Adam(learning_rate=0.001), loss="mse")
model.summary()
model.fit(X_train,
                    y_train,
                    epochs=1000,
                    batch_size=32,
                    validation_split=0.1,
                    callbacks=[keras.callbacks.EarlyStopping(monitor='val_loss', patience=5, mode='min')],
                    shuffle=False)


# Mean Absolute Error loss
X_train_pred = model.predict(X_train)
train_mae_loss = np.mean(np.abs(X_train_pred - X_train), axis=1)



# Set reconstruction error threshold
threshold = np.max(train_mae_loss)

print('Reconstruction error threshold:',threshold)


X_test_pred = model.predict(X_test, verbose=1)
test_mae_loss = np.mean(np.abs(X_test_pred-X_test), axis=1)
print(X_test_pred)
# Find anomalies
anomaly_df = pd.DataFrame(test[0:])
anomaly_df['loss'] = test_mae_loss
anomaly_df['threshold'] = threshold
anomaly_df['anomaly'] = anomaly_df['loss'] < anomaly_df['threshold']

anomaly_df.head()
