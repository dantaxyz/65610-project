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

import numpy
from numpy.fft import fft as nfft, ifft as nifft, fft2 as nfft2, ifft2 as nifft2


def fft(x):
    """
    fft function that is simply a wrapper around numpy's (very fast) FFT,
    modified to correct the scaling factor to be consistent with 6.300's
    definitions.
    """
    if isinstance(x, list):
        x = numpy.array(x)
        islist = True
    else:
        islist = False
    out = nfft(x) / (x.size)
    return out.tolist() if islist else out


def ifft(x):
    """
    Similarly, a wrapper around numpy's IFFT to correct the scaling factor to
    be consistent with 6.300's definitions.
    """
    if isinstance(x, list):
        x = numpy.array(x)
        islist = True
    else:
        islist = False
    out = nifft(x) * (x.size)
    return out.tolist() if islist else out


def fft2(x):
    """
    fft function that is simply a wrapper around numpy's (very fast) 2-D FFT,
    modified to correct the scaling factor to be consistent with 6.300's
    definitions.
    """
    x = numpy.array(x)
    return nfft2(x) / (x.size)


def ifft2(x):
    """
    Similarly, a wrapper around numpy's 2-D IFFT to correct the scaling factor to
    be consistent with 6.300's definitions.
    """
    x = numpy.array(x)
    return nifft2(x) * (x.size)
