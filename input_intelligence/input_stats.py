import math 



# calculate the length of the data in characters and bytes
def calculate_length(data) :
    
    charecters = len(data)

    bytes_length = len(data.encode('utf-8'))

    return charecters, bytes_length



# calculate the frequency of each character in the data
def calculate_frequency(data) :
    
    frequency = {}
    for char in data :
        if char in frequency :
            frequency[char] += 1
        else :
            frequency[char] = 1

    return frequency




#calculate the entropy of the data using Shannon's formula  
def calculate_entropy(data):

    raw_data = data.encode("utf-8")

    if len(raw_data) == 0:
        return 0

    frequency = {}

    for byte in raw_data:

        if byte in frequency:
            frequency[byte] += 1

        else:
            frequency[byte] = 1

    total_bytes = len(raw_data)

    entropy = 0

    for count in frequency.values():

        probability = count / total_bytes

        entropy = entropy - (
            probability * math.log2(probability)
        )

    return entropy