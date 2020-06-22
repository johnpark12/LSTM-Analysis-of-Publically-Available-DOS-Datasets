import numpy as np
import math

NUMBER_OF_LINES = 10000
FILENAME = "shuf-final.csv"
# FILENAME "final_dataset.csv"

# Read in and format the data
# Filter out only relevant fields
# RELEVANT_FIELDS = {"Num":"Sequence", 
#                    "Src IP": "boolean", 
#                    "Src Port": "boolean", 
#                    "Dst IP": "boolean", 
#                    "Dst Port": "boolean", 
#                 #    "Protocol": "text", 
#                    "Timestamp": "none", 
#                    "Flow Duration": "number",
#                    "timeSince": "number"}
# This is the point when I realized that I was working with flows.
RELEVANT_FIELDS = {
            'Src IP': "boolean", 
            'Src Port': "boolean", 
            'Dst IP': "boolean", 
            'Dst Port': "boolean", 
            'Protocol': "boolean",  
            'Flow Duration': "number", 
            'Tot Fwd Pkts': "number", 
            'Tot Bwd Pkts': "number", 
            'TotLen Fwd Pkts': "number", 
            'TotLen Bwd Pkts': "number", 
            'Fwd Pkt Len Max': "number", 
            'Fwd Pkt Len Min': "number", 
            'Fwd Pkt Len Mean': "number", 
            'Fwd Pkt Len Std': "number", 
            'Bwd Pkt Len Max': "number", 
            'Bwd Pkt Len Min': "number", 
            'Bwd Pkt Len Mean': "number", 
            'Bwd Pkt Len Std': "number", 
            'Flow Byts/s': "number", 
            'Flow Pkts/s': "number", 
            'Flow IAT Mean': "number", 
            'Flow IAT Std': "number", 
            'Flow IAT Max': "number", 
            'Flow IAT Min': "number", 
            'Fwd IAT Tot': "number", 
            'Fwd IAT Mean': "number", 
            'Fwd IAT Std': "number", 
            'Fwd IAT Max': "number", 
            'Fwd IAT Min': "number", 
            'Bwd IAT Tot': "number", 
            'Bwd IAT Mean': "number", 
            'Bwd IAT Std': "number", 
            'Bwd IAT Max': "number", 
            'Bwd IAT Min': "number",
            'Fwd PSH Flags': "boolean",
            'Bwd PSH Flags': "boolean",
            'Fwd URG Flags': "boolean",
            'Bwd URG Flags': "boolean",
            'Fwd Header Len': "number",
            'Bwd Header Len': "number",
            'Fwd Pkts/s': "number",
            'Bwd Pkts/s': "number",
            'Pkt Len Min': "number",
            'Pkt Len Max': "number",
            'Pkt Len Mean': "number",
            'Pkt Len Std': "number",
            'Pkt Len Var': "number",
            'FIN Flag Cnt': "number",
            'SYN Flag Cnt': "number",
            'RST Flag Cnt': "number",
            'PSH Flag Cnt': "number",
            'ACK Flag Cnt': "number",
            'URG Flag Cnt': "number",
            'CWE Flag Count': "number",
            'ECE Flag Cnt': "number",
            'Down/Up Ratio': "number",
            'Pkt Size Avg': "number",
            'Fwd Seg Size Avg': "number",
            'Bwd Seg Size Avg': "number",
            'Fwd Byts/b Avg': "number",
            'Fwd Pkts/b Avg': "number",
            'Fwd Blk Rate Avg': "number",
            'Bwd Byts/b Avg': "number",
            'Bwd Pkts/b Avg': "number",
            'Bwd Blk Rate Avg': "number",
            'Subflow Fwd Pkts': "number",
            'Subflow Fwd Byts': "number",
            'Subflow Bwd Pkts': "number",
            'Subflow Bwd Byts': "number",
            'Init Fwd Win Byts': "number",
            'Init Bwd Win Byts': "number",
            'Fwd Act Data Pkts': "number",
            'Fwd Seg Size Min': "number",
            'Active Mean': "number",
            'Active Std': "number",
            'Active Max': "number",
            'Active Min': "number",
            'Idle Mean': "number",
            'Idle Std': "number", 
            'Idle Max': "number", 
            'Idle Min': "number"}

print(f"Working with {len(RELEVANT_FIELDS)} fields")

nums = []
allData = []
allLabels = []
with open(FILENAME) as f:
    firstLine = f.readline()
    keys = [x.strip() for x in firstLine.split(",")[1:-1]]
    print(keys)
    for l in f:
        line = [x.strip() for x in l.split(",")]
        nums.append(line.pop(0))
        allLabels.append(line.pop())
        assert(len(keys) == len(line))
        entry = {k:v for k,v in zip(keys, line) if k in RELEVANT_FIELDS.keys()}
        for k,v in entry.items():
            if RELEVANT_FIELDS[k]=="number":
                entry[k] = np.float(v) if v else np.float(0)
        allData.append(entry)
        if (len(allData) == NUMBER_OF_LINES):
            break

print(f'Got {allLabels.count("ddos")} DDOS and {allLabels.count("Benign")} Benign')

# Turning labels into numbers
labelDict = {"ddos":1.0, "Benign":0.0}
allLabels = [labelDict[x] for x in allLabels]

# Shuffling
# For now, assume that nums doesn't matter
assert(len(allData) == len(allLabels))
temp = np.array(list(zip(allData, allLabels)))
np.random.shuffle(temp)
allData = [x[0] for x in temp]
allLabels = [x[1] for x in temp]
assert(len(allData) == len(allLabels))
for d in allData:
    assert(len(d) == len(allData[0]))

print(f"allData has {len(allData)} elements with {len(allData[0])} per data")

# Data Normalization
# Apply tokenizer for each field that isn't a number
# Gotta use binary for all non-numerical.
# For now, I'll avoid everything that's text. Gotta implement Bag of Words at a later date.
# Loop through the fields and do it one by one. Construct a new list from the results.
# Going to do the lazy approach. Start with one col, then two cols if necessary, then three, etc.
# The types are numerical, text, and boolean.
# Numerical will be normalized to [-1,1]. Ideally would use statistical methods here, but for now
# we just divide by the max value then minus by the mean.
# Boolean will be lazy added columns.
from sklearn import preprocessing

class binarizer:
    def __init__(self, allData):
        self.ref = list(set(allData))
        self.num = math.ceil(math.log2(len(self.ref)))
    def transform(self, data):
        i = self.ref.index(data)
        b = bin(i)[2:]
        return [0 for i in range(self.num-len(b))] + [int(x) for x in b]

normData = [np.array([]) for i in range(len(allData))]
lb = preprocessing.LabelBinarizer()
totalCols = 0
for key, value in RELEVANT_FIELDS.items():
    skip = []
    skip += ['Src IP' ]
    skip += ['Src Port' ]
    skip += ['Dst IP' ]
    skip += ['Dst Port' ]
    ## 99.8% up to here
    skip += ['Protocol'  ]
    skip += ['Flow Duration' ]
    skip += ['Tot Fwd Pkts' ]
    ## 98.5% up to here
    skip += ['Tot Bwd Pkts' ]
    skip += ['TotLen Fwd Pkts' ]
    skip += ['TotLen Bwd Pkts' ]
    skip += ['Fwd Pkt Len Max' ]
    skip += ['Fwd Pkt Len Min' ]
    skip += ['Fwd Pkt Len Mean' ]
    skip += ['Fwd Pkt Len Std' ]
    ## 98.8% up to here
    skip += ['Bwd Pkt Len Max' ]
    skip += ['Bwd Pkt Len Min' ]
    skip += ['Bwd Pkt Len Mean' ]
    skip += ['Bwd Pkt Len Std' ]
    skip += ['Flow Byts/s' ]
    skip += ['Flow Pkts/s' ]
    skip += ['Flow IAT Mean' ]
    skip += ['Flow IAT Std' ]
    skip += ['Flow IAT Max' ]
    ## 98.5 up to here
    # skip += ['Flow IAT Min' ]
    # skip += ['Fwd IAT Tot' ]
    # skip += ['Fwd IAT Mean' ]
    # skip += ['Fwd IAT Std' ]
    # skip += ['Fwd IAT Max' ]
    # skip += ['Fwd IAT Min' ]
    # skip += ['Bwd IAT Tot' ]
    # skip += ['Bwd IAT Mean' ]
    # skip += ['Bwd IAT Std' ]
    ## 98.5 up to here
    # skip += ['Bwd IAT Max' ]
    # skip += ['Bwd IAT Min']
    # skip += ['Fwd PSH Flags']
    # skip += ['Bwd PSH Flags']
    # skip += ['Fwd URG Flags']
    # skip += ['Bwd URG Flags']
    # skip += ['Fwd Header Len']
    # skip += ['Bwd Header Len']
    # skip += ['Fwd Pkts/s']
    # skip += ['Bwd Pkts/s']
    ## 98.5
    # skip += ['Pkt Len Min']
    # skip += ['Pkt Len Max']
    # skip += ['Pkt Len Mean']
    # skip += ['Pkt Len Std']
    # skip += ['Pkt Len Var']
    # skip += ['FIN Flag Cnt']
    # skip += ['SYN Flag Cnt']
    # skip += ['RST Flag Cnt']
    # skip += ['PSH Flag Cnt']
    ## 96.6
    # skip += ['ACK Flag Cnt']
    # skip += ['URG Flag Cnt']
    # skip += ['CWE Flag Count']
    # skip += ['ECE Flag Cnt']
    # skip += ['Down/Up Ratio']
    # skip += ['Pkt Size Avg']
    # skip += ['Fwd Seg Size Avg']
    # skip += ['Bwd Seg Size Avg']
    ## 91
    # skip += ['Fwd Byts/b Avg']
    # skip += ['Fwd Pkts/b Avg']
    # skip += ['Fwd Blk Rate Avg']
    # skip += ['Bwd Byts/b Avg']
    # skip += ['Bwd Pkts/b Avg']
    # skip += ['Bwd Blk Rate Avg']
    # skip += ['Subflow Fwd Pkts']
    # skip += ['Subflow Fwd Byts']
    ## 93
    # skip += ['Subflow Bwd Pkts']
    # skip += ['Subflow Bwd Byts']
    # skip += ['Init Fwd Win Byts']
    # skip += ['Init Bwd Win Byts']
    # skip += ['Fwd Act Data Pkts']
    ## 91
    skip += ['Fwd Seg Size Min']  ## This seems to be a critical point.
    ## But even if I leave this out and bring the other points back in, we're getting really good 
    ## results. 
    ## 57.4
    # skip += ['Active Mean']
    # skip += ['Active Std']
    # skip += ['Active Max']
    # skip += ['Active Min']
    # skip += ['Idle Mean']
    # skip += ['Idle Std' ]
    # skip += ['Idle Max' ]
    # skip += ['Idle Min']
    if key in skip: # Still 99.8% accuracy.
        print(f"Skipping {key}")
        continue
    oldcollen = len(normData[0])
    allValues = [x[key] for x in allData]
    if value == "boolean":
        # lb.fit(allValues)
        b = binarizer(allValues)
        # print(f"working with classes {b.ref}")
        for i in range(len(allData)):
            # encoded = lb.transform([allValues[i]])
            # normData[i] = np.concatenate((normData[i],encoded[0]))
            encoded = b.transform(allValues[i])
            normData[i] = np.concatenate((normData[i],encoded))
        # for i in range(len(allData)):
        #     normData[i].append()
    elif value == "number":
        # Minor bug - if inf found, we replace with max to norm to 1.
        maxVal = np.where(np.isinf(allValues),-np.Inf,allValues).argmax()
        for i in range(len(allValues)):
            if (allValues[i] == np.float("inf")):
                allValues[i] = maxVal
        newValues = preprocessing.maxabs_scale(allValues)
        for i in range(len(allData)):
            normData[i] = np.concatenate((normData[i],np.array([newValues[i]])))
    else:
        raise Exception("what did you just hand me?")
    newcollen = len(normData[0])
    totalCols += newcollen-oldcollen
    print(f"Normalized {key} considered a {value} by adding {newcollen-oldcollen} cols")
print(f"Total cols added per item is {totalCols}")
print(len(normData))
print(normData[0].shape)
# Gotta Tensor-ify everything, if possible.

# Segment the data into sliding window
# Normally, I would window. But the nature of the data and the sheer size of it means that it isn't necessary.
# WINDOW_SIZE = 100
# data_windows = []
# for i in range(NUMBER_OF_LINES - WINDOW_SIZE):
#     pass

# Break up data into training and eval.
# Since there's just so much data available, I won't bother with tricks such as rotational segmentation.
TRAIN_RATIO = 0.9
TRAIN_LEN = int(len(normData)*TRAIN_RATIO)
training_data = normData[:TRAIN_LEN]
training_labels = allLabels[:TRAIN_LEN]
testing_data = normData[TRAIN_LEN:]
testing_labels = allLabels[TRAIN_LEN:]
print(training_data[0].shape)
print(testing_data[0].shape)

training_data = np.array(training_data).reshape(-1,1,len(training_data[0]))
training_labels = np.array(training_labels)
testing_data = np.array(testing_data).reshape(-1,1,len(testing_data[0]))
testing_labels = np.array(testing_labels)

print(f"Shape of training data is {training_data.shape}")
print(f"Shape of testing data is {testing_data.shape}")
print(f"First value in training is {training_data[0]}")
print(f"First 10 training labels {training_labels[:10]}")
print(f"First value in testing is {testing_data[0]}")
print(f"First 10 testing labels {testing_labels[:10]}")
print(f"Training on {np.count_nonzero(training_labels==1)} and {np.count_nonzero(training_labels==0)} Benign")
print(f"Testing on {np.count_nonzero(testing_labels==1)} and {np.count_nonzero(testing_labels==0)} Benign")

# At this point, we gotta check that we normalized everything properly
# ASSERT testing should go here.

# Building the LSTM NN


# Training
EPOCHS = 10

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, LSTM#, CuDNNLSTM

model = Sequential()

# IF you are running with a GPU, try out the CuDNNLSTM layer type instead (don't pass an activation, tanh is required)
model.add(LSTM(85, activation='relu', return_sequences=True))
# model.add(Dropout(0.2))

model.add(LSTM(128, activation='relu'))
# model.add(Dropout(0.1))

model.add(Dense(32, activation='relu'))
# model.add(Dropout(0.2))

model.add(Dense(10, activation='softmax'))

opt = tf.keras.optimizers.Adam(lr=0.001, decay=1e-6)

# Compile model
model.compile(
    loss='sparse_categorical_crossentropy',
    optimizer=opt,
    metrics=['accuracy'],
)

model.fit(training_data,
          training_labels,
          epochs=EPOCHS,
          validation_data=(testing_data, testing_labels))

# Evaluating