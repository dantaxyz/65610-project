# This file is part of lib6300 library for MIT 6.300 (Signal Processing)
# Copyright (c) 2018-2019 by adam hartz <hz@mit.edu>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import sys
import wave
import numpy
import tempfile

from . import wavfile

try:
    import pyaudio
except:
    pyaudio = None

_normalize_funcs = {
    "int32": lambda d: d / 2147483648,
    "int16": lambda d: d / 32768,
    "uint8": lambda d: d / 256 - 0.5,
}


def wav_read(fname):
    """
    Read a wave file.  This will always convert to mono.

    Arguments:
      * fname: a string containing a file name of a WAV file.

    Returns a tuple with 2 elements:
      * a 1-dimensional NumPy array with floats in the range [-1, 1]
        representing samples.  the length of this array will be the number of
        samples in the given wave file.
      * an integer containing the sample rate
    """
    # load in data, convert to float
    fs, data = wavfile.read(fname)
    type_ = data.dtype.name
    data = data.astype(float)

    # convert stereo to mono
    if len(data.shape) > 2:
        raise Exception("too many channels!")
    elif len(data.shape) == 2:
        data = data.mean(1)

    # normalize to range [-1, 1]
    try:
        data = _normalize_funcs[type_](data)
    except KeyError:
        pass

    return data.tolist(), fs


def wav_write(samples, fs, fname):
    """
    Write a wave file.

    Arguments:
      * samples: a Python list of numbers in the range [-1, 1], one for each
                 sample in the output WAV file.  Numbers in the list that are
                 outside this range will be clipped to -1 or 1.
      * fs: an integer representing the sampling rate of the output
            (samples/second).
      * fname: a string containing a file name of the WAV file to be written.
    """
    out = numpy.array(samples)
    out[out > 1.0] = 1.0
    out[out < -1.0] = -1.0
    out = (out * 32767).astype("int16")
    wavfile.write(fname, fs, out)


def wav_play(samples, fs):
    """
    Play WAV data from a Python object and a sampling rate.  REQUIRES PYAUDIO.

    Arguments:
      * samples: a Python list of numbers in the range [-1, 1], one for each
                 sample in the output WAV file.  Numbers in the list that are
                 outside this range will be clipped to -1 or 1.
      * fs: an integer representing the sampling rate of the output
            (samples/second).
    """
    if pyaudio is None:
        print(
            "pyaudio is required for playing WAV files directly from lib6300.",
            file=sys.stderr,
            flush=True,
        )
        return
    filename = os.path.join(
        tempfile.gettempdir(), "6300_wave_%s.wav" % abs(hash((fs, tuple(samples))))
    )
    wav_write(samples, fs, filename)
    f = wave.open(filename, "r")
    try:
        p = pyaudio.PyAudio()
        stream = p.open(
            format=p.get_format_from_width(f.getsampwidth()),
            channels=f.getnchannels(),
            rate=f.getframerate(),
            output=True,
        )

        data = f.readframes(10240)
        while data:
            stream.write(data)
            data = f.readframes(10240)

        stream.stop_stream()
        stream.close()
        p.terminate()
    finally:
        f.close()
        os.unlink(filename)


def wav_file_play(fname):
    """
    Play audio from a WAV file on disk using wav_play.  REQUIRES PYAUDIO.

    Arguments:
      * fname: a string containing a file name of the WAV file to be written.
    """
    wav_play(*wav_read(fname))
