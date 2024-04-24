import numpy as np
from lib6300.wavfile import read as _wav_read, write as _wav_write
import IPython.display as ipd

def read_wav(filename):
    fs, input = _wav_read(filename=filename)
    input = input.mean(1) # convert to mono
    return input, fs

def modify_lsb(audio, message):
    message_bits = np.unpackbits(np.array([x for x in message]).astype("uint8"))
    if len(message_bits) > len(audio):
        raise Exception("audio file not large enough")
    return np.concatenate([[(int(x) & ~1) | b for x, b in zip(audio, message)], audio[len(message):]]).astype(audio.dtype)

def read_lsb(audio):
    message_bits = [int(x) & 1 for x in audio]
    return np.packbits(message_bits).tobytes()

def write_wav(audio, fs, filename):
    _wav_write(filename = filename, rate = fs, data = audio)