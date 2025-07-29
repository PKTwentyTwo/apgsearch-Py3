#*************************************
# * Ash Pattern Generator (apgsearch) *
# *************************************
# * Version: v1.2 Py3 (adapted by PK22)     *
# *************************************
#
# -- Processes roughly 100 soups per (second . core . GHz), using caching
#    and machine-learning to optimise itself during runtime.
#
# -- Can perfectly identify oscillators with period < 1000, well-separated
#    spaceships of low period, and certain infinite-growth patterns (such
#    guns and puffers, including both naturally-occurring types of switch
#    engine).
#
# -- Separates most pseudo-objects into their constituent parts, including
#    all pseudo-still-lifes of 18 or fewer live cells (which is the maximum
#    theoretically possible, given there is a 19-cell pseudo-still-life
#    with two distinct decompositions). 
#
# -- Correctly separates non-interacting standard spaceships, irrespective
#    of their proximity. In particular, a LWSS-on-LWSS is registered as two
#    LWSSes, whereas an LWSS-on-HWSS is registered as a single spaceship
#    (since they interact by suppressing sparks).
#
# -- At least 99.9999999999% reliable at identifying objects in asymmetrical
#    soups in B3/S23 (based on the fact that out of over 10^12 objects that
#    have appeared, there are no errors).
#
# -- Scores soups based on the total excitement of the ash objects.
#
# -- Support for other outer-totalistic rules, including detection and
#    classification of various types of infinite growth.
#
# -- Support for symmetrical soups.
#
# -- Uploads results to the server at https://catagolue.hatsya.com (which
#    currently has collected over 2.7 * 10^12 objects).
#
# -- Peer-reviews others' contributions to ensure data integrity for the
#    asymmetrical B3/S23 census.
#
# By Adam P. Goucher, with contributions from Andrew Trevorrow, Tom Rokicki,
# Nathaniel Johnston, Dave Greene and Richard Schank.
#
#New features in adapted script:
#
# -- Code is for Python 3, instead of Python 2, allowing it to be used with the latest versions of Golly.
#
# -- New symmetries implemented, based on a hacked version by wwei47 - 4x64, 2x128, 1x256, 1x256X2, and 1x256X2+1.
#
# -- New pseudo-object symmetries - enter 'Pseudo_<symmetry>_Test' as the symmetry to count pseudo patterns (and upload to a seperate census)
#
# -- Haul verification removed to avoid wrongly rejecting good hauls.
#
# -- Support for INT rules, based on praosylen's hacked version of apgsearch.
#
# -- Program-side verification to ensure erroneous objects are removed before uploading to a census.
#
# --Support for inflated symmetries (add the prefix 'i' to a symmetry of your choice), although they are quite slow.

#=Credits=#
#Original script by Adam P. Goucher
#Adaptations for Python 3 and support for pseudo-object and inflated symmetries by PK22
#Additional symmetries from wwei47's adaptation of apgsearch - see https://conwaylife.com/forums/viewtopic.php?f=9&t=1480&p=48266&hilit=1x256X2+1#p48266
#Support for INT rules from praosylen's adaptation of apgsearch - see https://conwaylife.com/forums/viewtopic.php?p=50149#p50149
#Bug identification and reports from users such as rabbit, Resu, and Yujh helped to improve the script, as did feature suggestions from Resu
#Pseudo-object symmetries inspired by Yujh's Pseudo C1 census




'''
Copyright 2015 Adam P. Goucher

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
'''

import golly as g
import time
import math
import operator
import hashlib
import datetime
import os
import urllib.request, urllib.error, urllib.parse

def get_server_address():
    # Should be 'https://catagolue.hatsya.com' for the released version,
    # and 'https://localhost:8080' for the development version:    
    return 'https://catagolue.hatsya.com'


# Engages with Catagolue's authentication system ('payment over SHA-256',
# affectionately abbreviated to 'payosha256'):
#
# The payosha256_key can be obtained from logging into Catagolue in your
# web browser and visiting https://catagolue.hatsya.com/payosha256
def authenticate(payosha256_key, operation_name):

    g.show("Authenticating with Catagolue via the payosha256 protocol...")

    payload = "payosha256:get_token:"+payosha256_key+":"+operation_name
    payload = payload.encode('utf-8')
    req = urllib.request.Request(get_server_address() + "/payosha256", payload, {"Content-type": "text/plain"})
    try:
        f = urllib.request.urlopen(req)
    except:
        g.show('Unable to connect to Catagolue! Maybe check your internet connection?')
        return None
    if (f.getcode() != 200):
        return None

    resp = f.read()
    
    lines = resp.splitlines()

    for line in lines:
        parts = line.decode('utf-8').split(':')

        if (len(parts) < 3):
            continue

        if (parts[1] != 'good'):
            continue

        target = parts[2]
        token = parts[3]

        g.show("Token " + token + " obtained from payosha256. Performing proof of work with target " + target + "...")

        for nonce in range(100000000):

            prehash = token + ":" + str(nonce)
            posthash = hashlib.sha256(prehash.encode('utf-8')).hexdigest()

            if (posthash < target):
                break

        if (posthash > target):
            continue

        g.show("String "+prehash+" is sufficiently valuable ("+posthash+" < "+target+").")

        payload = "payosha256:pay_token:"+prehash+"\n"

        return payload

    return None

# Sends the results to Catagolue:
def catagolue_results(results, payosha256_key, operation_name, endpoint="/apgsearch", return_point=None):

    #try:

        payload = authenticate(payosha256_key, operation_name)


        if payload is None:
            return 1

        # Concatenate results to payload
        payload += results  
        # Prepare the request
        req = urllib.request.Request(
            url=get_server_address() + endpoint,
            data=payload.encode('utf-8'),
            headers={"Content-type": "text/plain"}
        )

        
        with urllib.request.urlopen(req) as f:  # Use `with` to ensure the response is closed properly
            if f.getcode() != 200:
                g.warn('Unable to connect to Catagolue!')
                return 2

            resp = f.read()
        
        try:
            f2 = open("catagolue-response.txt", 'w')
            f2.write(resp.decode('utf-8'))
            f2.close()
            if resp.decode('utf-8').count('Payosha256 authentication succeeded.\n***********************************************') == 0:
                g.warn(resp.decode('utf-8'))
            if return_point is not None:
                #return_point.pop(0)
                #returnpoint.insert(0, resp)
                return_point[0] = resp.decode('utf-8')
            
        except:
            g.warn("Unable to save catagolue response file.")

        # Update return_point if needed
        if return_point is not None:
            return_point[0] = resp
        return 0

        



# Takes approximately 350 microseconds to construct a 16-by-16 soup based
# on a SHA-256 cryptographic hash in the obvious way.
def hashsoup(instring, sym):
    global inflationamount
    s = hashlib.sha256(instring.encode('utf-8')).digest()
    thesoup = []
    

    if sym in ['D2_x', 'D8_1', 'D8_4', 'Pseudo_D2_x_Test', 'Pseudo_D8_1_Test', 'Pseudo_D8_4_Test']:
        d = 1
    elif sym in ['D4_x1', 'D4_x4', 'Pseudo_D4_x1_Test', 'Pseudo_D4_x4_Test']:
        d = 2
    else:
        d = 0
        
    for j in range(32):

        t = (s[j])

        for k in range(8):

            if (sym in ['8x32', 'Pseudo_8x32_Test']):
                
                x = k + 8*(j % 4)
                y = int(j / 4)
                
            elif (sym in ['4x64', 'Pseudo_4x64_Test']):
                
                x = k + 8*(j % 8)
                y = int(j / 8)
        
            elif (sym in ['2x128', 'Pseudo_2x128_Test']):
                
                x = k + 8*(j % 16)
                y = int(j / 16)
                
            elif (sym in ['1x256', '1x256X2', '1x256X2+1', 'Pseudo_1x256_Test', 'Pseudo_1x256X2_Test', 'Pseudo_1x256X2+1_Test']):
                
                x = k + 8*(j % 32)
                y = int(j / 32)
                
            else:
                
                x = k + 8*(j % 2)
                y = int(j / 2)

            if (t & (1 << (7 - k))):
                
                if ((d == 0) | (x >= y)):

                    thesoup.append(x)
                    thesoup.append(y)
                elif (sym in ['D4_x1', 'Pseudo_D4_x1_Test']):

                    thesoup.append(y)
                    thesoup.append(-x)

                elif (sym in ['D4_x4', 'Pseudo_D4_x4_Test']):

                    thesoup.append(y)
                    thesoup.append(-x-1)
                #The above elif statements were too far down, and I spent about an hour searching for the issue. Finding logic errors is hard.
                if (sym in ['1x256X2+1', 'Pseudo_1x256X2+1_Test']):

                    thesoup.append(-x)
                    thesoup.append(y)

                if (sym in ['1x256X2', 'Pseudo_1x256X2_Test']):

                    thesoup.append(-1-x)
                    thesoup.append(y)
                
                if (sym in ['32x32', 'Pseudo_32x32_Test']):

                    thesoup.append(x+16)
                    thesoup.append(y)
                    thesoup.append(x)
                    thesoup.append(y+16)
                    thesoup.append(x+16)
                    thesoup.append(y+16)

                if (sym in ['75p', 'Pseudo_75p_Test']):

                    thesoup.append(16-y)
                    thesoup.append(x)

                if ((sym in ['D4_x1', 'Pseudo_D4_x1_Test']) & (x == y)):

                    thesoup.append(y)
                    thesoup.append(-x)

                if ((sym in ['D4_x4', 'Pseudo_D4_x4_Test']) & (x == y)):

                    thesoup.append(y)
                    thesoup.append(-x-1)

    # Checks for diagonal symmetries:
    if (d >= 1):
        for x in range(0, len(thesoup), 2):
            thesoup.append(thesoup[x+1])
            thesoup.append(thesoup[x])
        if d == 2:
            if (sym == 'D4_x1' or sym == 'Pseudo_D4_x1_Test'):
                for x in range(0, len(thesoup), 2):
                    thesoup.append(-thesoup[x+1])
                    thesoup.append(-thesoup[x])
            else:
                for x in range(0, len(thesoup), 2):
                    thesoup.append(-thesoup[x+1] - 1)
                    thesoup.append(-thesoup[x] - 1)
            for i in range(inflationamount):
                thenewsoup = []
                for x in range(len(thesoup)//2):
                    thenewsoup = thenewsoup + [thesoup[x*2]*2, thesoup[x*2+1]*2,thesoup[x*2]*2+1, thesoup[x*2+1]*2,thesoup[x*2]*2, thesoup[x*2+1]*2+1,thesoup[x*2]*2+1, thesoup[x*2+1]*2+1]
                thesoup = thenewsoup
            return thesoup

    # Checks for orthogonal x symmetry:
    if sym in ['D2_+1', 'D4_+1', 'D4_+2', 'Pseudo_D2_+1_Test', 'Pseudo_D4_+1_Test', 'Pseudo_D4_+2_Test']:
        for x in range(0, len(thesoup), 2):
            thesoup.append(thesoup[x])
            thesoup.append(-thesoup[x+1])
    elif sym in ['D2_+2', 'D4_+4', 'Pseudo_D2_+2_Test', 'Pseudo_D4_+4_Test']:
        for x in range(0, len(thesoup), 2):
            thesoup.append(thesoup[x])
            thesoup.append(-thesoup[x+1] - 1)

    # Checks for orthogonal y symmetry:
    if sym in ['D4_+1', 'Pseudo_D4_+1_Test']:
        for x in range(0, len(thesoup), 2):
            thesoup.append(-thesoup[x])
            thesoup.append(thesoup[x+1])
    elif sym in ['D4_+2', 'D4_+4', 'Pseudo_D4_+2_Test', 'Pseudo_D4_+4_Test']:
        for x in range(0, len(thesoup), 2):
            thesoup.append(-thesoup[x] - 1)
            thesoup.append(thesoup[x+1])

    # Checks for rotate2 symmetry:
    if sym in ['C2_1', 'C4_1', 'D8_1', 'Pseudo_C2_1_Test', 'Pseudo_C4_1_Test', 'Pseudo_D8_1_Test']:
        for x in range(0, len(thesoup), 2):
            thesoup.append(-thesoup[x])
            thesoup.append(-thesoup[x+1])
    elif sym in ['C2_2', 'Pseudo_C2_2_Test']:
        for x in range(0, len(thesoup), 2):
            thesoup.append(-thesoup[x])
            thesoup.append(-thesoup[x+1]-1)
    elif sym in ['C2_4', 'C4_4', 'D8_4', 'Pseudo_C2_4_Test', 'Pseudo_C4_4_Test', 'Pseudo_D8_4_Test']:
        for x in range(0, len(thesoup), 2):
            thesoup.append(-thesoup[x]-1)
            thesoup.append(-thesoup[x+1]-1)

    # Checks for rotate4 symmetry:
    if (sym in ['C4_1', 'D8_1', 'Pseudo_C4_1_Test', 'Pseudo_D8_1_Test']):
        for x in range(0, len(thesoup), 2):
            thesoup.append(thesoup[x+1])
            thesoup.append(-thesoup[x])
    elif (sym in ['C4_4', 'D8_4', 'Pseudo_C4_4_Test', 'Pseudo_D8_4_Test']):
        for x in range(0, len(thesoup), 2):
            thesoup.append(thesoup[x+1])
            thesoup.append(-thesoup[x]-1)
    for i in range(inflationamount):
                thenewsoup = []
                for x in range(len(thesoup)//2):
                    thenewsoup = thenewsoup + [thesoup[x*2]*2, thesoup[x*2+1]*2,thesoup[x*2]*2+1, thesoup[x*2+1]*2,thesoup[x*2]*2, thesoup[x*2+1]*2+1,thesoup[x*2]*2+1, thesoup[x*2+1]*2+1]
                thesoup = thenewsoup
    return thesoup




# Obtains a canonical representation of any oscillator/spaceship that (in
# some phase) fits within a 40-by-40 bounding box. This representation is
# alphanumeric and lowercase, and so much more compact than RLE. Compare:
#
# Common name: pentadecathlon
# Canonical representation: 4r4z4r4
# Equivalent RLE: 2bo4bo$2ob4ob2o$2bo4bo!
#
# It is a generalisation of a notation created by Allan Weschler in 1992.
def canonise(duration):

    representation = "#"

    # We need to compare each phase to find the one with the smallest
    # description:
    for t in range(duration):

        rect = g.getrect()
        if (len(rect) == 0):
            return "0"

        if ((rect[2] <= 40) & (rect[3] <= 40)):
            # Fits within a 40-by-40 bounding box, so eligible to be canonised.
            # Choose the orientation which results in the smallest description:
            representation = compare_representations(representation, canonise_orientation(rect[2], rect[3], rect[0], rect[1], 1, 0, 0, 1))
            representation = compare_representations(representation, canonise_orientation(rect[2], rect[3], rect[0]+rect[2]-1, rect[1], -1, 0, 0, 1))
            representation = compare_representations(representation, canonise_orientation(rect[2], rect[3], rect[0], rect[1]+rect[3]-1, 1, 0, 0, -1))
            representation = compare_representations(representation, canonise_orientation(rect[2], rect[3], rect[0]+rect[2]-1, rect[1]+rect[3]-1, -1, 0, 0, -1))
            representation = compare_representations(representation, canonise_orientation(rect[3], rect[2], rect[0], rect[1], 0, 1, 1, 0))
            representation = compare_representations(representation, canonise_orientation(rect[3], rect[2], rect[0]+rect[2]-1, rect[1], 0, -1, 1, 0))
            representation = compare_representations(representation, canonise_orientation(rect[3], rect[2], rect[0], rect[1]+rect[3]-1, 0, 1, -1, 0))
            representation = compare_representations(representation, canonise_orientation(rect[3], rect[2], rect[0]+rect[2]-1, rect[1]+rect[3]-1, 0, -1, -1, 0))

        g.run(1)

    return representation

# A subroutine used by canonise:
def canonise_orientation(length, breadth, ox, oy, a, b, c, d):

    representation = ""

    chars = "0123456789abcdefghijklmnopqrstuvwxyz"

    for v in range(int((breadth-1)/5)+1):
        zeroes = 0
        if (v != 0):
            representation += "z"
        for u in range(length):
            baudot = 0
            for w in range(5):
                x = ox + a*u + b*(5*v + w)
                y = oy + c*u + d*(5*v + w)
                baudot = (baudot >> 1) + 16*g.getcell(x, y)
            if (baudot == 0):
                zeroes += 1
            else:
                if (zeroes > 0):
                    if (zeroes == 1):
                        representation += "0"
                    elif (zeroes == 2):
                        representation += "w"
                    elif (zeroes == 3):
                        representation += "x"
                    else:
                        representation += "y"
                        representation += chars[zeroes - 4]
                zeroes = 0
                representation += chars[baudot]
    return representation

# Compares strings first by length, then by lexicographical ordering.
# A hash character is worse than anything else.
def compare_representations(a, b):

    if (a == "#"):
        return b
    elif (b == "#"):
        return a
    elif (len(a) < len(b)):
        return a
    elif (len(b) < len(a)):
        return b
    elif (a < b):
        return a
    else:
        return b

# Finds the gradient of the least-squares regression line corresponding
# to a list of ordered pairs:
def regress(pairlist):

    cumx = 0.0
    cumy = 0.0
    cumvar = 0.0
    cumcov = 0.0

    for x,y in pairlist:

        cumx += x
        cumy += y

    cumx = cumx / len(pairlist)
    cumy = cumy / len(pairlist)

    for x,y in pairlist:

        cumvar += (x - cumx)*(x - cumx)
        cumcov += (x - cumx)*(y - cumy)

    return (cumcov / cumvar)

# Analyses a pattern whose average population follows a power-law:
def powerlyse(stepsize, numsteps):

    g.setalgo("HashLife")
    g.setbase(2)
    g.setstep(stepsize)

    poplist = [0]*numsteps

    poplist[0] = int(g.getpop())

    pointlist = []

    for i in range(1, numsteps, 1):

        g.step()
        poplist[i] = int(g.getpop()) + poplist[i-1]

        if (i % 50 == 0):

            g.fit()
            g.update()

        if (i > numsteps/2):

            pointlist.append((math.log(i),math.log(poplist[i]+1.0)))

    power = regress(pointlist)

    if (power < 1.10):
        return "unidentified"
    elif (power < 1.65):
        return "zz_REPLICATOR"
    elif (power < 2.05):
        return "zz_LINEAR"
    elif (power < 2.8):
        return "zz_EXPLOSIVE"
    else:
        return "zz_QUADRATIC"

# Gets the period of an interleaving of degree-d polynomials:
def deepperiod(sequence, maxperiod, degree):

    for p in range(1, maxperiod, 1):

        good = True

        for i in range(maxperiod):

            diffs = [0] * (degree + 2)
            for j in range(degree + 2):

                diffs[j] = sequence[i + j*p]

            # Produce successive differences:
            for j in range(degree + 1):
                for k in range(degree + 1):
                    diffs[k] = diffs[k] - diffs[k + 1]

            if (diffs[0] != 0):
                good = False
                break

        if (good):
            return p
    return -1

# Analyses a linear-growth pattern, returning a hash:
def linearlyse(maxperiod):

    poplist = [0]*(3*maxperiod)

    for i in range(3*maxperiod):

        g.run(1)
        poplist[i] = int(g.getpop())

    p = deepperiod(poplist, maxperiod, 1)

    if (p == -1):
        return "unidentified"

    difflist = [0]*(2*maxperiod)

    for i in range(2*maxperiod):

        difflist[i] = poplist[i + p] - poplist[i]

    q = deepperiod(difflist, maxperiod, 0)

    moments = [0, 0, 0]

    for i in range(p):

        moments[0] += (poplist[i + q] - poplist[i])
        moments[1] += (poplist[i + q] - poplist[i]) ** 2
        moments[2] += (poplist[i + q] - poplist[i]) ** 3

    prehash = str(moments[1]) + "#" + str(moments[2])

    # Linear-growth patterns with growth rate zero are clearly errors!
    if (moments[0] == 0):
        return "unidentified"

    return "yl" + str(p) + "_" + str(q) + "_" + str(moments[0]) + "_" + hashlib.md5(prehash.encode('utf-8')).hexdigest()

    
# This explodes pseudo-still-lifes and pseudo-oscillators into their
# constituent parts.
#
# -- Requires the period (if oscillatory) and graph-theoretic diameter
#    to not exceed 4096.
# -- Never mistakenly separates a true object.
# -- Correctly separates most pseudo-still-lifes, including the famous:
#    https://www.conwaylife.com/wiki/Quad_pseudo_still_life
# -- Works perfectly for all still-lifes of up to 17 bits.
# -- Doesn't separate 'locks', of which the smallest example has 18
#    bits and is unique:
#
#     ** **
#     ** **
#
#    * *** *
#    ** * **
#
# To use this function (standalone), merely copy it into a script of
# the following form:
#
#   import golly as g
#
#   def pseudo_bangbang():
#
#   [...]
#
#   pseudo_bangbang()
#
# and execute it in Golly with a B3/S23 universe containing any still-
# lifes or oscillators you want to separate. Pure objects correspond to
# connected components in the final state of the universe.
#
# This has dependencies on the rules ContagiousLife, PercolateInfection
# and EradicateInfection.
#
# Not to be confused with the Unix shell instruction for repeating the
# previous instruction as a superuser (sudo !!), or indeed with any
# parodies of this song: https://www.youtube.com/watch?v=YswhUHH6Ufc
#
# Adam P. Goucher, 2014-08-25
def pseudo_bangbang(alpharule):

    g.setrule("APG_ContagiousLife_" + alpharule)
    g.setbase(2)
    g.setstep(12)
    g.step()

    celllist = g.getcells(g.getrect())

    for i in range(0, len(celllist)-1, 3):
        
        # Only infect cells that haven't yet been infected:
        if (g.getcell(celllist[i], celllist[i+1]) <= 2):

            # Seed an initial 'infected' (red) cell:
            g.setcell(celllist[i], celllist[i+1], g.getcell(celllist[i], celllist[i+1]) + 2)

            prevpop = 0
            currpop = int(g.getpop())

            # Continue infecting until the entire component has been engulfed:
            while (prevpop != currpop):

                # Percolate the infection to every cell in the island:
                g.setrule("APG_PercolateInfection")
                g.setbase(2)
                g.setstep(12)
                g.step()

                # Transmit the infection across any bridges.
                g.setrule("APG_ContagiousLife_" + alpharule)
                g.setbase(2)
                g.setstep(12)
                g.step()

                prevpop = currpop
                currpop = int(g.getpop())
                
            g.fit()
            g.update()

            # Red becomes green:
            g.setrule("APG_EradicateInfection")
            g.step()


# Counts the number of live cells of each degree:
def degreecount():

    celllist = g.getcells(g.getrect())
    counts = [0,0,0,0,0,0,0,0,0]

    for i in range(0, len(celllist), 2):

        x = celllist[i]
        y = celllist[i+1]

        degree = -1

        for ux in range(x - 1, x + 2):
            for uy in range(y - 1, y + 2):

                degree += g.getcell(ux, uy)

        counts[degree] += 1

    return counts

# Counts the number of live cells of each degree in generations 1 and 2:
def degreecount2():

    g.run(1)
    a = degreecount()
    g.run(1)
    b = degreecount()

    return (a + b)

# If the universe consists only of disjoint *WSSes, this will return
# a triple (l, w, h) giving the quantities of each *WSS. Otherwise,
# this function will return (-1, -1, -1).
#
# This should only be used to separate period-4 moving objects which
# may contain multiple *WSSes.
def countxwsses():

    degcount = degreecount2()
    if (degreecount2() != degcount):
        # Degree counts are not period-2:
        return (-1, -1, -1)

    # Degree counts of each standard spaceship:
    hwssa = [1,4,6,2,0,0,0,0,0,0,0,0,4,4,6,1,2,1]
    mwssa = [2,2,5,2,0,0,0,0,0,0,0,0,4,4,4,1,2,0]
    lwssa = [1,2,4,2,0,0,0,0,0,0,0,0,4,4,2,2,0,0]
    hwssb = [0,0,0,4,4,6,1,2,1,1,4,6,2,0,0,0,0,0]
    mwssb = [0,0,0,4,4,4,1,2,0,2,2,5,2,0,0,0,0,0]
    lwssb = [0,0,0,4,4,2,2,0,0,1,2,4,2,0,0,0,0,0]

    # Calculate the number of standard spaceships in each phase:
    hacount = degcount[17]
    macount = degcount[16]/2 - hacount
    lacount = (degcount[15] - hacount - macount)/2
    hbcount = degcount[8]
    mbcount = degcount[7]/2 - hbcount
    lbcount = (degcount[6] - hbcount - mbcount)/2

    # Determine the expected degcount given the calculated quantities:
    pcounts = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    pcounts = list(map(lambda x, y: x + y, pcounts, [hacount*x for x in hwssa]))
    pcounts = list(map(lambda x, y: x + y, pcounts, [macount*x for x in mwssa]))
    pcounts = list(map(lambda x, y: x + y, pcounts, [lacount*x for x in lwssa]))
    pcounts = list(map(lambda x, y: x + y, pcounts, [hbcount*x for x in hwssb]))
    pcounts = list(map(lambda x, y: x + y, pcounts, [mbcount*x for x in mwssb]))
    pcounts = list(map(lambda x, y: x + y, pcounts, [lbcount*x for x in lwssb]))

    # Compare the observed and expected degcounts (to eliminate nonstandard spaceships):
    if (pcounts != degcount):
        # Expected and observed values do not match:
        return (-1, -1, -1)

    # Return the combined numbers of *WSSes:
    return(lacount + lbcount, macount + mbcount, hacount + hbcount)


# Generates the helper rules for apgsearch, given a base outer-totalistic rule.
class RuleGenerator:

    # Unless otherwise specified, assume standard B3/S23 rule:
    bee = [False, False, False, True, False, False, False, False, False]
    ess = [False, False, True, True, False, False, False, False, False]
    alphanumeric = "B3S23"
    slashed = "B3/S23"
    ruletype = True
    notationdict = {
        "0"  : [0,0,0,0,0,0,0,0],   #    
        "1e" : [1,0,0,0,0,0,0,0],   #   N
        "1c" : [0,1,0,0,0,0,0,0],   #   NE
        "2a" : [1,1,0,0,0,0,0,0],   #   N,  NE
        "2e" : [1,0,1,0,0,0,0,0],   #   N,  E
        "2k" : [1,0,0,1,0,0,0,0],   #   N,  SE
        "2i" : [1,0,0,0,1,0,0,0],   #   N,  S
        "2c" : [0,1,0,1,0,0,0,0],   #   NE, SE
        "2n" : [0,1,0,0,0,1,0,0],   #   NE, SW
        "3a" : [1,1,1,0,0,0,0,0],   #   N,  NE, E
        "3n" : [1,1,0,1,0,0,0,0],   #   N,  NE, SE
        "3r" : [1,1,0,0,1,0,0,0],   #   N,  NE, S
        "3q" : [1,1,0,0,0,1,0,0],   #   N,  NE, SW
        "3j" : [1,1,0,0,0,0,1,0],   #   N,  NE, W
        "3i" : [1,1,0,0,0,0,0,1],   #   N,  NE, NW
        "3e" : [1,0,1,0,1,0,0,0],   #   N,  E,  S
        "3k" : [1,0,1,0,0,1,0,0],   #   N,  E,  SW
        "3y" : [1,0,0,1,0,1,0,0],   #   N,  SE, SW
        "3c" : [0,1,0,1,0,1,0,0],   #   NE, SE, SW
        "4a" : [1,1,1,1,0,0,0,0],   #   N,  NE, E,  SE
        "4r" : [1,1,1,0,1,0,0,0],   #   N,  NE, E,  S
        "4q" : [1,1,1,0,0,1,0,0],   #   N,  NE, E,  SW
        "4i" : [1,1,0,1,1,0,0,0],   #   N,  NE, SE, S
        "4y" : [1,1,0,1,0,1,0,0],   #   N,  NE, SE, SW
        "4k" : [1,1,0,1,0,0,1,0],   #   N,  NE, SE, W
        "4n" : [1,1,0,1,0,0,0,1],   #   N,  NE, SE, NW
        "4z" : [1,1,0,0,1,1,0,0],   #   N,  NE, S,  SW
        "4j" : [1,1,0,0,1,0,1,0],   #   N,  NE, S,  W
        "4t" : [1,1,0,0,1,0,0,1],   #   N,  NE, S,  NW
        "4w" : [1,1,0,0,0,1,1,0],   #   N,  NE, SW, W
        "4e" : [1,0,1,0,1,0,1,0],   #   N,  E,  S,  W
        "4c" : [0,1,0,1,0,1,0,1],   #   NE, SE, SW, NW
        "5i" : [1,1,1,1,1,0,0,0],   #   N,  NE, E,  SE, S
        "5j" : [1,1,1,1,0,1,0,0],   #   N,  NE, E,  SE, SW
        "5n" : [1,1,1,1,0,0,1,0],   #   N,  NE, E,  SE, W
        "5a" : [1,1,1,1,0,0,0,1],   #   N,  NE, E,  SE, NW
        "5q" : [1,1,1,0,1,1,0,0],   #   N,  NE, E,  S,  SW
        "5c" : [1,1,1,0,1,0,1,0],   #   N,  NE, E,  S,  W
        "5r" : [1,1,0,1,1,1,0,0],   #   N,  NE, SE, S,  SW
        "5y" : [1,1,0,1,1,0,1,0],   #   N,  NE, SE, S,  W
        "5k" : [1,1,0,1,0,1,1,0],   #   N,  NE, SE, SW, W
        "5e" : [1,1,0,1,0,1,0,1],   #   N,  NE, SE, SW, NW
        "6a" : [1,1,1,1,1,1,0,0],   #   N,  NE, E,  SE, S,  SW
        "6c" : [1,1,1,1,1,0,1,0],   #   N,  NE, E,  SE, S,  W
        "6k" : [1,1,1,1,0,1,1,0],   #   N,  NE, E,  SE, SW, W
        "6e" : [1,1,1,1,0,1,0,1],   #   N,  NE, E,  SE, SW, NW
        "6n" : [1,1,1,0,1,1,1,0],   #   N,  NE, E,  S,  SW, W
        "6i" : [1,1,0,1,1,1,0,1],   #   N,  NE, SE, S,  SW, NW
        "7c" : [1,1,1,1,1,1,1,0],   #   N,  NE, E,  SE, S,  SW, W
        "7e" : [1,1,1,1,1,1,0,1],   #   N,  NE, E,  SE, S,  SW, NW
        "8"  : [1,1,1,1,1,1,1,1],   #   N,  NE, E,  SE, S,  SW, W,  NW
        }
    
    allneighbours = [  
        ["0"],
        ["1e", "1c"],
        ["2a", "2e", "2k", "2i", "2c", "2n"],
        ["3a", "3n", "3r", "3q", "3j", "3i", "3e", "3k", "3y", "3c"],
        ["4a", "4r", "4q", "4i", "4y", "4k", "4n", "4z", "4j", "4t", "4w", "4e", "4c"],
        ["5i", "5j", "5n", "5a", "5q", "5c", "5r", "5y", "5k", "5e"],
        ["6a", "6c", "6k", "6e", "6n", "6i"],
        ["7c", "7e"],
        ["8"],
        ]
        
    allneighbours_flat = [n for x in allneighbours for n in x]
    ntbee = {}
    ntess = {}

    # Save all helper rules:
    def saveAllRules(self):
        
        self.saveClassifyObjects()
        self.saveCoalesceObjects()
        self.saveExpungeObjects()
        self.saveExpungeGliders()
        self.saveIdentifyGliders()
        self.saveHandlePlumes()
        self.savePercolateInfection()
        self.saveEradicateInfection()
        self.saveContagiousLife()
        self.savePropagateClassifications()
        self.saveDecayer()
        self.saveTreeMaker()
##        if self.t:
##            self.saveIdentifyTs()
##            self.saveAdvanceTs()
##            self.saveAssistTs()
##            self.saveExpungeTs()
        
    def testPattern(self, clist, period, moving):
        g.new("Test pattern")
        g.setalgo("QuickLife")
        g.setrule(self.slashed)
        g.putcells(clist)
        r = g.getrect()
        h = g.hash(r)
        g.run(period)
        f = g.getrect()
        if int(g.getpop()) == 0:
            return False
        return h == g.hash(f) and (moving and f != r) or (not moving and f == r)
    
    #To use this standalone, just copy this into a separate file and add the lines
    '''import golly as g
class Foo:
    slashed = g.getstring("Enter name of rule to test", "Life")'''
    #before it and the lines
    '''foo = Foo()
g.show(foo.testHensel())'''
    #after it, and run it in Golly.
    def testHensel(self):
        #Dict containing all possible transitions:
        dict = { 
                 "0"  : "0,0,0,0,0,0,0,0",
                 "1e" : "1,0,0,0,0,0,0,0",  #   N 
                 "1c" : "0,1,0,0,0,0,0,0",  #   NE
                 "2a" : "1,1,0,0,0,0,0,0",  #   N,  NE
                 "2e" : "1,0,1,0,0,0,0,0",  #   N,  E 
                 "2k" : "1,0,0,1,0,0,0,0",  #   N,  SE
                 "2i" : "1,0,0,0,1,0,0,0",  #   N,  S 
                 "2c" : "0,1,0,1,0,0,0,0",  #   NE, SE
                 "2n" : "0,1,0,0,0,1,0,0",  #   NE, SW
                 "3a" : "1,1,1,0,0,0,0,0",  #   N,  NE, E
                 "3n" : "1,1,0,1,0,0,0,0",  #   N,  NE, SE 
                 "3r" : "1,1,0,0,1,0,0,0",  #   N,  NE, S      
                 "3q" : "1,1,0,0,0,1,0,0",  #   N,  NE, SW
                 "3j" : "1,1,0,0,0,0,1,0",  #   N,  NE, W
                 "3i" : "1,1,0,0,0,0,0,1",  #   N,  NE, NW
                 "3e" : "1,0,1,0,1,0,0,0",  #   N,  E,  S
                 "3k" : "1,0,1,0,0,1,0,0",  #   N,  E,  SW
                 "3y" : "1,0,0,1,0,1,0,0",  #   N,  SE, SW     
                 "3c" : "0,1,0,1,0,1,0,0",  #   NE, SE, SW 
                 "4a" : "1,1,1,1,0,0,0,0",  #   N,  NE, E,  SE
                 "4r" : "1,1,1,0,1,0,0,0",  #   N,  NE, E,  S  
                 "4q" : "1,1,1,0,0,1,0,0",  #   N,  NE, E,  SW
                 "4i" : "1,1,0,1,1,0,0,0",  #   N,  NE, SE, S
                 "4y" : "1,1,0,1,0,1,0,0",  #   N,  NE, SE, SW
                 "4k" : "1,1,0,1,0,0,1,0",  #   N,  NE, SE, W
                 "4n" : "1,1,0,1,0,0,0,1",  #   N,  NE, SE, NW 
                 "4z" : "1,1,0,0,1,1,0,0",  #   N,  NE, S,  SW
                 "4j" : "1,1,0,0,1,0,1,0",  #   N,  NE, S,  W
                 "4t" : "1,1,0,0,1,0,0,1",  #   N,  NE, S,  NW
                 "4w" : "1,1,0,0,0,1,1,0",  #   N,  NE, SW, W
                 "4e" : "1,0,1,0,1,0,1,0",  #   N,  E,  S,  W
                 "4c" : "0,1,0,1,0,1,0,1",  #   NE, SE, SW, NW
                 "5a" : "0,0,0,1,1,1,1,1",  #   SE, S,  SW, W,  NW
                 "5n" : "0,0,1,0,1,1,1,1",  #   E,  S,  SW, W,  NW
                 "5r" : "0,0,1,1,0,1,1,1",  #   E,  SE, SW, W,  
                 "5q" : "0,0,1,1,1,0,1,1",  #   E,  SE, S,  W,  NW
                 "5j" : "0,0,1,1,1,1,0,1",  #   E,  SE, S,  SW, NW 
                 "5i" : "0,0,1,1,1,1,1,0",  #   E,  SE, S,  SW, W 
                 "5e" : "0,1,0,1,0,1,1,1",  #   NE, SE, SW, W,  NW, 
                 "5k" : "0,1,0,1,1,0,1,1",  #   NE, SE, S,  W,  NW
                 "5y" : "0,1,1,0,1,0,1,1",  #   NE, E,  S,  W, NW 
                 "5c" : "1,0,1,0,1,0,1,1",  #   N,  E,  S,  W,  NW
                 "6a" : "0,0,1,1,1,1,1,1",  #   E,  SE, S,  SW, W,  NW
                 "6e" : "0,1,0,1,1,1,1,1",  #   NE, SE, S,  SW, W,  NW
                 "6k" : "0,1,1,0,1,1,1,1",  #   NE, E,  S,  SW, W,  NW
                 "6i" : "0,1,1,1,0,1,1,1",  #   NE, E,  SE, SW, W,  NW
                 "6c" : "1,0,1,0,1,1,1,1",  #   N,  E,  S,  SW, W,  NW
                 "6n" : "1,0,1,1,1,0,1,1",  #   N,  E,  SE, S,  W,  NW
                 "7e" : "0,1,1,1,1,1,1,1",  #   NE, E,  SE, S,  SW, W,  NW 
                 "7c" : "1,0,1,1,1,1,1,1",  #   N,  E,  SE, S,  SW, W,  NW
                 "8"  : "1,1,1,1,1,1,1,1",
                }
        
        #Represents the encoding in dict:
        neighbors = [(-1,0),(-1,1),(0,1),(1,1),(1,0),(1,-1),(0,-1),(-1,-1)]
        
        #Will store transitions temporarily:
        d2 = [{},{}]
        
        #Used to help a conversion later:
        lnums = []
        for i in range(9):
            lnums.append([j for j in dict if int(j[0]) == i])
        
        #Self-explanatory:
        g.setrule(self.slashed)
        
        #Test each transition in turn:
        for i in range(2):
            for j in dict:
                j2 = dict[j].split(",")
                g.new("Testing Hensel notation...")
                for k in range(len(j2)):
                    k2 = int(j2[k])
                    g.setcell(neighbors[k][0], neighbors[k][1], k2)
                g.setcell(0, 0, i)
                g.run(1)
                d2[i][j] = int(g.getcell(0, 0)) == 1
        
        #Will become the main table of transitions:
        trans_ = [[],[]]
        
        #Will become the final output string:
        not_ = "B"
        for i in range(2):
            #Convert d2 to a more usable form
            for j in range(9):
                trans_[i].append({})
                for k in lnums[j]:
                    trans_[i][j][k] = d2[i][k]
                    
            #Make each set of transitions:
            for j in range(9):
                
                #Number of present transitions for B/S[[j]]
                sum = 0
                for k in trans_[i][j]:
                    if trans_[i][j][k]:
                        sum += 1
                
                #No transitions present:
                if sum == 0:
                    continue
                
                #All transitions present:
                if sum == len(trans_[i][j]):
                    not_ += str(j)
                    continue
                    
                str_ = str(j) #Substring for current set of transitions
                
                #Minus sign needed if more than half of 
                #current transition set is present.
                minus = (sum >= len(trans_[i][j])/2)
                if minus:
                    str_ += "-"
                
                str2 = "" #Another substring for current transition set
                
                #Write transitions:
                for k in trans_[i][j]:
                    if trans_[i][j][k] != minus:
                        str2 += k[1:]
                
                #Append transitions:
                not_ += str_ + "".join(sorted(str2))
                
            if i == 0:
                not_ += "S"
                
        g.new("Test finished.")
        return not_
    
    # Interpret birth or survival string
    def ruleparts(self, part):

        inverse = False
        nlist = []
        totalistic = True
        rule = {}
        for k in self.notationdict:
            rule[k] = False
        
        # Reverse the rule string to simplify processing
        part = part[::-1]
        
        for c in part:
            if c.isdigit():
                d = int(c)
                if totalistic:
                    # Add all the neighbourhoods for this value
                    for neighbour in self.allneighbours[d]:
                        rule[neighbour] = True
                elif inverse:
                    # Add all the neighbourhoods not in nlist for this value
                    for neighbour in self.allneighbours[d]:
                        if neighbour[1] not in nlist:
                            rule[neighbour] = True
                else:
                    # Add all the neighbourhoods in nlist for this value
                    for n in nlist:
                        neighbour = c + n
                        if neighbour in rule:
                            rule[neighbour] = True
                        else:
                            # Error
                            return {}
                    
                inverse = False
                nlist = []
                totalistic = True

            elif (c == '-'):
                inverse = True

            else:
                totalistic = False
                nlist.append(c)
        
        return rule

    # Set isotropic, non-totalistic rule
    # Adapted from something adapted from Eric Goldstein's HenselNotation->Ruletable(1.3).py
    def nt_setrule(self, rulestring):
    
        # neighbours_flat = [n for x in neighbours for n in x]
        b = {}
        s = {}
        sep = ''
        birth = ''
        survive = ''
        
        rulestring = rulestring.lower()
        
        if '/' in rulestring:
            sep = '/'
        elif '_' in rulestring:
            sep = '_'
        elif (rulestring[0] == 'b'):
            sep = 's'
        else:
            sep = 'b'
        
        survive, birth = rulestring.split(sep)
        if (survive[0] == 'b'):
            survive, birth = birth, survive
        survive = survive.replace('s', '')
        birth = birth.replace('b', '')
        
        b = self.ruleparts(birth)
        s = self.ruleparts(survive)

        if b and s:
            self.alphanumeric = 'B' + birth + 'S' + survive
            self.slashed = 'B' + birth + 'S' + survive
            self.hensel = 'B' + birth + 'S' + survive
            self.ntbee = b
            self.ntess = s
            self.rulepath = g.getdir("rules") + self.alphanumeric + ".rule"
        else:
            # Error
            g.note("Unable to process rule definition.\n" +
                    "b = " + str(b) + "\ns = " + str(s))
            g.exit()
    
    # Set outer-totalistic or isotropic non-totalistic rule:
    def setrule(self, rulestring):
        
        # Prevent annoying Golly warnings that pause the script and make it nearly
        # impossible to exit.
        rulestring = rulestring.replace("b", "B").replace("s", "S")
        
        mode = 0 #
        s = [False]*9
        b = [False]*9
        
        #Outer-totalistic
        #if '/' in rulestring:
        if not len(list(filter(lambda c: c in "acdefghijklmnopqrtuvwxyz", rulestring))):
            for c in rulestring:

                if ((c == 's') | (c == 'S')):
                    mode = 0

                if ((c == 'b') | (c == 'B')):
                    mode = 1

                if (c == '/'):
                    mode = 1 - mode

                if ((ord(c) >= 48) & (ord(c) <= 56)):
                    d = ord(c) - 48
                    if (mode == 0):
                        s[d] = True
                    else:
                        b[d] = True

            prefix = "B"
            suffix = "S"

            for i in range(9):
                if (b[i]):
                    prefix += str(i)
                if (s[i]):
                    suffix += str(i)

            self.alphanumeric = prefix + suffix
            self.slashed = prefix + "/" + suffix
            self.hensel = self.alphanumeric
            self.bee = b
            self.ess = s
            self.t = False
            self.g = self.ess[2] & self.ess[3] & (not self.ess[1]) & (not self.ess[4])
            self.g = self.g & (not (self.bee[4] | self.bee[5]))
        #Non-totalistic
        else:
            rulestring = rulestring.replace("/", "_")
            self.ruletype = False
            self.t = self.testPattern([1,0,0,1,1,1,2,1], 5, True)
            self.g = self.testPattern([0,0,1,0,2,0,0,1,1,2], 4, True)
            if os.path.exists(g.getdir("app") + "Rules/" + rulestring + ".rule"):
                self.rulepath = g.getdir("app") + "Rules/" + rulestring + ".rule"
            elif os.path.exists(g.getdir("rules") + rulestring + ".rule"):
                self.rulepath = g.getdir("rules") + rulestring + ".rule"
            else:
                self.nt_setrule(rulestring)
                self.saveIsotropicRule()
                return
            self.alphanumeric = rulestring
            self.slashed = rulestring
            self.hensel = self.testHensel()
            #Leave bee and ess alone; we don't know what we're dealing with, so default to Life.
    # Save a rule file:
    def saverule(self, name, comments, table, colours):

        ruledir = g.getdir("rules")
        filename = ruledir + name + ".rule"

        results = "@RULE " + name + "\n\n"
        results += "*** File autogenerated by saverule. ***\n\n"
        results += comments
        results += "\n\n@TABLE\n\n"
        results += table
        results += "\n\n@COLORS\n\n"
        results += colours

        # Only create a rule file if it doesn't already exist; this avoids
        # concurrency issues when booting an instance of apgsearch whilst
        # one is already running.
        if not os.path.exists(filename):
            try:
                f = open(filename, 'w')
                f.write(results)
                f.close()
            except:
                g.warn("Unable to create rule table:\n" + filename)

    # Defines a variable:
    def newvar(self, name, vallist):

        line = "var "+name+"={"
        for i in range(len(vallist)):
            if (i > 0):
                line += ','
            line += str(vallist[i])
        line += "}\n"

        return line

    # Defines a block of equivalent variables:
    def newvars(self, namelist, vallist):

        block = ""

        for name in namelist:
            block += self.newvar(name, vallist)

        block += "\n"

        return block

    def scoline(self, chara, charb, left, right, amount):     #Second and third parameters not to be confused with Beta Canum Venaticorum and the main victim of a 2015 Paris terrorist attack, respectively.

        line = str(left) + ","

        for i in range(8):
            if (i < amount):
                line += chara
            else:
                line += charb
            line += chr(97 + i)
            line += ","

        line += str(right) + "\n"

        return line
    
    def saveIsotropicRule(self):
    
        comments = """
This is a two state, isotropic, non-totalistic rule on the Moore neighbourhood.
The notation used to define the rule was originally proposed by Alan Hensel.
See https://www.ibiblio.org/lifepatterns/neighbors2.html for details
"""

        table = """
n_states:2
neighborhood:Moore
symmetries:rotate4reflect
"""

        table += self.newvars(["a","b","c","d","e","f","g","h"], [0, 1])

        table += "\n# Birth\n"
        for n in self.allneighbours_flat:
            if self.ntbee[n]:
                table += "0,"
                table += str(self.notationdict[n])[1:-1].replace(' ','')
                table += ",1\n"
        
        table += "\n# Survival\n"
        for n in self.allneighbours_flat:
            if self.ntess[n]:
                table += "1,"
                table += str(self.notationdict[n])[1:-1].replace(' ','')
                table += ",1\n"

        table += "\n# Death\n"
        table += self.scoline("","",1,0,0)
        
        colours = ""
        self.saverule(self.alphanumeric, comments, table, colours)
    
    def saveHandlePlumes(self):

        comments = """
This post-processes the output of ClassifyObjects to remove any
unwanted clustering of low-period objects appearing in puffer
exhaust.

state 0:  vacuum

state 7:  ON, still-life
state 8:  OFF, still-life

state 9:  ON, p2 oscillator
state 10: OFF, p2 oscillator

state 11: ON, higher-period object
state 12: OFF, higher-period object
"""
        table = """
n_states:18
neighborhood:Moore
symmetries:permute

var da={0,2,4,6,8,10,12,14,16}
var db={0,2,4,6,8,10,12,14,16}
var dc={0,2,4,6,8,10,12,14,16}
var dd={0,2,4,6,8,10,12,14,16}
var de={0,2,4,6,8,10,12,14,16}
var df={0,2,4,6,8,10,12,14,16}
var dg={0,2,4,6,8,10,12,14,16}
var dh={0,2,4,6,8,10,12,14,16}

var a={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var b={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var c={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var d={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var e={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var f={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var g={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var h={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}


8,da,db,dc,dd,de,df,dg,dh,0
10,da,db,dc,dd,de,df,dg,dh,0

9,a,b,c,d,e,f,g,h,1
10,a,b,c,d,e,f,g,h,2
"""
        colours = """
1  255  255  255
2  127  127  127
7    0    0  255
8    0    0  127
9  255    0    0
10 127    0    0
11   0  255    0
12   0  127    0
"""
        self.saverule("APG_HandlePlumesCorrected", comments, table, colours)

    def saveExpungeGliders(self):

        comments = """
This removes unwanted gliders.
It is mandatory that one first runs the rules CoalesceObjects,
IdentifyGliders and ClassifyObjects.

Run this for two generations, and observe the population
counts after 1 and 2 generations. This will give the
following data:

number of gliders = (p(1) - p(2))/5
"""
        table = """
n_states:18
neighborhood:Moore
symmetries:rotate4reflect

var a={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var b={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var c={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var d={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var e={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var f={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var g={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var h={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}

13,a,b,c,d,e,f,g,h,14
14,a,b,c,d,e,f,g,h,0
"""
        colours = """
0    0    0    0
1  255  255  255
2  127  127  127
7    0    0  255
8    0    0  127
9  255    0    0
10 127    0    0
11   0  255    0
12   0  127    0
13 255  255    0
14 127  127    0
"""
        self.saverule("APG_ExpungeGliders", comments, table, colours)

    def saveIdentifyGliders(self):

        comments = """
Run this after CoalesceObjects to find any gliders.

state 0:  vacuum
state 1:  ON
state 2:  OFF
"""
        table = """
n_states:18
neighborhood:Moore
symmetries:rotate4reflect

var a={0,2}
var b={0,2}
var c={0,2}
var d={0,2}
var e={0,2}
var f={0,2}
var g={0,2}
var h={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var i={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var j={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var k={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var l={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var m={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var n={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var o={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var p={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
var q={3,4}
var r={9,10}
var s={11,12}

1,1,a,1,1,b,1,c,d,3
d,1,1,1,1,a,b,1,c,4

3,i,j,k,l,m,n,o,p,5
4,i,j,k,l,m,n,o,p,6

1,q,i,j,a,b,c,k,l,7
d,q,i,j,a,b,c,k,l,8
1,i,a,b,c,d,e,j,q,7
f,i,a,b,c,d,e,j,q,8

5,7,8,7,7,8,7,8,8,9
6,7,7,7,7,8,8,7,8,10
5,i,j,k,l,m,n,o,p,15
6,i,j,k,l,m,n,o,p,16
15,i,j,k,l,m,n,o,p,1
16,i,j,k,l,m,n,o,p,2

7,i,j,k,l,m,n,o,p,11
8,i,j,k,l,m,n,o,p,12

9,i,j,k,l,m,n,o,p,13
10,i,j,k,l,m,n,o,p,14
11,r,j,k,l,m,n,o,p,13
11,i,r,k,l,m,n,o,p,13
12,r,j,k,l,m,n,o,p,14
12,i,r,k,l,m,n,o,p,14

11,i,j,k,l,m,n,o,p,1
12,i,j,k,l,m,n,o,p,2
"""
        colours = """
0    0    0    0
1  255  255  255
2  127  127  127
7    0    0  255
8    0    0  127
9  255    0    0
10 127    0    0
11   0  255    0
12   0  127    0
13 255  255    0
14 127  127    0
"""
        self.saverule("APG_IdentifyGliders", comments, table, colours)
    
    def saveIdentifyTs(self):
    
        comments = """
To identify the common spaceship xq4_27, also known as the T.

state 0:  vacuum
state 11:  p3+ on
state 12:  p3+ off
state 13:  T on
state 14:  T off
state 15:  not-T on
state 16:  not-T off
"""
        table = """
n_states:18
neighborhood:Moore
symmetries:rotate4reflect
var a={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17}
var aa=a
var ab=a
var ac=a
var ad=a
var ae=a
var af=a
var ag=a
var o={0,2,12,14}
var oa=o
var ob=o
var oc=o
var od=o
var s={5,6,17}
var sa=s
var sb=s
var sc=s
var n={7,8,9,10,11,15,16}
var xo={2,4,6,14}
var xn={1,3,5,13,17}
var i={11,12}
var io={0,1,2,11,12}
var ioa=io
var b={0,12}
11,11,o,12,11,12,11,12,oa,1
11,11,12,o,oa,io,oc,od,12,1
11,12,11,o,oa,ob,oc,12,12,1
11,12,12,12,12,12,12,12,12,1
11,12,11,o,oa,ob,oc,od,11,1
11,11,o,11,oa,11,io,io,io,1
11,11,11,11,11,12,o,oa,ob,1
11,11,11,o,oa,io,ob,oc,11,1
11,11,11,o,oa,ob,oc,12,12,1
11,11,o,11,oa,11,io,ioa,io,1
11,11,12,11,12,11,12,o,0,1
11,11,11,11,io,ioa,o,oa,ob,1
11,11,11,o,oa,ob,oc,od,12,1
12,11,o,11,oa,11,12,12,12,2
12,11,11,o,oa,ob,oc,11,12,2
12,11,12,12,11,12,11,12,12,2
12,11,12,12,11,i,o,oa,ob,2
12,11,12,12,o,oa,ob,12,12,2
b,11,11,o,io,oa,ioa,ob,11,2
12,11,11,12,o,o,oa,ob,ob,2
12,11,11,11,11,12,o,oa,ob,2
b,11,11,11,o,oa,ob,oc,od,2
1,1,2,1,2,1,2,1,2,15
1,2,1,o,oa,ob,oc,od,1,3
1,1,o,2,1,2,1,2,oa,3
1,1,2,o,oa,io,oc,od,2,3
1,2,1,o,oa,ob,oc,2,2,3
1,2,2,2,2,2,o,oa,ob,3
1,1,o,1,oa,1,io,ioa,io,3
1,1,2,1,2,1,12,2,0,3
1,1,2,1,2,1,2,o,0,3
1,1,1,1,io,ioa,o,oa,ob,3
1,1,1,2,o,oa,ob,2,1,3
1,1,1,o,oa,ob,oc,od,2,3
1,1,1,2,2,1,2,2,1,3
2,1,2,2,1,2,1,2,2,4
2,1,2,2,1,12,12,12,2,12
2,1,12,2,1,2,12,12,12,12
2,1,o,12,a,aa,ab,12,oa,12
2,2,1,2,12,1,o,o,o,12
2,1,o,1,oa,1,2,2,2,4
2,1,1,o,oa,ob,oc,1,2,4
2,1,2,1,2,1,2,2,2,4
2,1,2,2,1,io,o,oa,ob,4
2,1,2,2,o,oa,ob,oc,od,4
2,1,1,o,io,oa,ioa,ob,1,4
2,1,1,2,o,oa,ob,oc,od,4
2,1,1,1,o,oa,ob,oc,od,4
2,1,1,1,1,2,o,oa,ob,4
4,3,3,4,3,4,3,4,3,6
6,3,3,4,3,4,3,4,3,4
4,3,4,3,4,3,4,4,4,6
6,3,4,3,4,3,4,4,4,4
3,3,3,3,3,3,4,3,4,5
5,3,3,3,3,3,4,3,4,3
3,3,4,3,4,3,4,4,4,5
5,3,4,3,4,3,4,4,4,3
3,3,3,4,4,3,4,4,3,5
5,3,3,4,4,3,4,4,3,3
3,5,5,4,12,12,12,4,4,17
3,s,a,aa,ab,ac,ad,ae,af,5
4,s,a,aa,ab,ac,ad,ae,af,6
3,a,s,aa,ab,ac,ad,ae,af,5
4,a,s,aa,ab,ac,ad,ae,af,6
6,12,6,5,5,6,o,oa,ob,12
6,s,sa,sb,a,aa,ab,ac,ad,14
6,s,sa,a,aa,ab,ac,ad,sb,14
5,s,sa,a,aa,ab,ac,ad,sb,13
5,s,sa,sb,a,aa,ac,ac,ad,13
6,13,o,oa,oa,14,13,6,14,12
17,14,14,13,13,14,12,12,12,13
14,17,13,14,o,oa,12,12,12,12
xn,n,a,aa,ab,ac,ad,ae,af,15
xo,n,a,aa,ab,ac,ad,ae,af,16
xn,a,n,aa,ab,ac,ad,ae,af,15
xo,a,n,aa,ab,ac,ad,ae,af,16
1,a,aa,ab,ac,ad,ae,af,ag,15
2,a,aa,ab,ac,ad,ae,af,ag,16
"""
        colours = """
0    0    0    0
1  255  255  255
2  127  127  127
7    0    0  255
8    0    0  127
9  255    0    0
10 127    0    0
11   0  255    0
12   0  127    0
13 255  255    0
14 127  127    0
17 127    0  127
"""
        self.saverule("APG_IdentifyTs", comments, table, colours)
    
    def saveAdvanceTs(self):
    
        comments = """
To filter out extraneous results from the output of APG_IdentifyTs.

state 0:  vacuum
state 11:  p3+ on
state 12:  p3+ off
state 13:  T on
state 14:  T off
state 15:  not-T on
state 16:  not-T off
"""
        table = """
n_states:18
neighborhood:Moore
symmetries:rotate4reflect
var a={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17}
var aa=a
var ab=a
var ac=a
var ad=a
var ae=a
var af=a
var ag=a
var in={1,3,5,15}
var io={2,4,6,16}
var i={1,2,3,4,5,6,15,16}
var o={0,12,14}
var oa=o
var ob=o
var oc=o
var od=o
var oe=o
var of=o
var og=o
var oo={12,14}
var c={0,12,13,14}
var ca=c
var t={13,14}
in,a,aa,ab,ac,ad,ae,af,ag,11
io,a,aa,ab,ac,ad,ae,af,ag,12
#Birth
o,13,13,13,oa,ob,oc,od,oe,13
o,13,13,oa,ob,13,oc,od,oe,13
o,13,13,oa,ob,oc,od,13,oe,13
o,13,13,oa,ob,oc,od,oe,13,13
o,13,oa,13,ob,13,oc,od,oe,13
o,13,oa,ob,13,oc,13,od,oe,13
#Inert
o,13,13,c,ca,oa,ob,oc,od,o
o,13,oa,c,ob,oc,od,oe,of,o
o,13,13,oa,13,ob,13,oc,13,o
o,oa,13,ob,c,oc,od,oe,of,o
o,13,oa,ob,13,oc,od,oe,of,o
o,13,oa,ob,oc,13,od,oe,of,o
o,13,13,oa,13,13,ob,oc,od,o
o,oa,13,ob,13,oc,13,od,13,o
o,oa,13,ob,oc,od,13,oe,of,o
#Survival
13,13,13,o,oa,ob,oc,od,c,13
13,13,o,13,oa,13,ob,oc,od,13
13,13,13,13,o,oa,ob,oc,od,13
13,c,o,oa,13,ob,13,oc,od,13
#Death
13,13,13,13,13,o,oa,ob,oc,14
13,13,13,13,13,13,o,c,oa,14
13,13,o,oa,ob,c,oc,od,oe,14
13,o,13,oa,ob,oc,od,oe,of,14
13,13,13,o,oa,13,ob,oc,13,14
13,o,oa,ob,oc,od,oe,of,og,14
#Not T
0,o,oa,ob,oc,od,oe,of,og,0
oo,o,oa,ob,oc,od,oe,of,og,12
o,a,aa,ab,ac,ad,ae,af,t,16
o,a,aa,ab,ac,ad,ae,t,af,16
13,a,aa,ab,ac,ad,ae,af,t,15
13,a,aa,ab,ac,ad,ae,t,af,15
"""
        colours = """
0    0    0    0
1  255  255  255
2  127  127  127
7    0    0  255
8    0    0  127
9  255    0    0
10 127    0    0
11   0  255    0
12   0  127    0
13 255  255    0
14 127  127    0
17 127    0  127
"""
        self.saverule("APG_AdvanceTs", comments, table, colours)

    def saveExpungeTs(self):
    
        comments = """
To filter out extraneous results from the output of APG_IdentifyTs.

state 0:  vacuum
state 11:  p3+ on
state 12:  p3+ off
state 13:  T on
state 14:  T off
state 17:  about to die
"""
        table = """
n_states:18
neighborhood:Moore
symmetries:rotate8reflect
var a={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17}
var aa=a
var ab=a
var ac=a
var ad=a
var ae=a
var af=a
var ag=a
var o={0,12,14}
var oa=o
var ob=o
var oc=o
var od=o
var oe=o
var of=o
var og=o
var t={13,14}
13,o,oa,ob,oc,od,oe,of,og,17
13,13,o,oa,ob,oc,od,oe,of,17
13,13,13,o,oa,ob,oc,od,oe,17
13,13,13,o,oa,ob,oc,od,13,17
13,13,o,13,oa,13,ob,oc,od,17
13,13,13,13,13,13,o,13,oa,17
14,o,oa,ob,oc,od,oe,of,og,12
17,a,aa,ab,ac,ad,ae,af,ag,0
t,17,a,aa,ab,ac,ad,ae,af,17
"""
        colours = """
0    0    0    0
1  255  255  255
2  127  127  127
7    0    0  255
8    0    0  127
9  255    0    0
10 127    0    0
11   0  255    0
12   0  127    0
13 255  255    0
14 127  127    0
17 127    0  127
"""
        self.saverule("APG_ExpungeTs", comments, table, colours)
        
    def saveAssistTs(self):
    
        comments = """
To help filter out extraneous results from the output of APG_IdentifyTs.

state 0:  vacuum
state 11:  p3+ on
state 12:  p3+ off
state 13:  T on
state 14:  T off
state 15:  not-T on
state 15:  not-T off
"""
        table = """
n_states:18
neighborhood:Moore
symmetries:rotate8reflect
var a={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17}
var aa=a
var ab=a
var ac=a
var ad=a
var ae=a
var af=a
var ag=a
var t={13,14}
var nt={15,16}
13,nt,a,ab,ac,ad,ae,af,ag,15
14,nt,a,ab,ac,ad,ae,af,ag,16
12,t,a,ab,ac,nt,ad,ae,af,16
"""
        colours = """
0    0    0    0
1  255  255  255
2  127  127  127
7    0    0  255
8    0    0  127
9  255    0    0
10 127    0    0
11   0  255    0
12   0  127    0
13 255  255    0
14 127  127    0
17 127    0  127
"""
        self.saverule("APG_AssistTs", comments, table, colours)

    def saveEradicateInfection(self):

        comments = """
To run after ContagiousLife to disinfect any cells in states 3, 4, 7, and 8.

state 0:  vacuum
state 1:  ON
state 2:  OFF
"""
        table = """
n_states:7
neighborhood:Moore
symmetries:permute

var a={0,1,2,3,4,5,6}
var b={0,1,2,3,4,5,6}
var c={0,1,2,3,4,5,6}
var d={0,1,2,3,4,5,6}
var e={0,1,2,3,4,5,6}
var f={0,1,2,3,4,5,6}
var g={0,1,2,3,4,5,6}
var h={0,1,2,3,4,5,6}
var i={0,1,2,3,4,5,6}

4,a,b,c,d,e,f,g,h,6
3,a,b,c,d,e,f,g,h,5
"""
        colours = """
0    0    0    0
1    0    0  255
2    0    0  127
3  255    0    0
4  127    0    0
5    0  255    0
6    0  127    0
7  255    0  255
8  127    0  127
"""
        self.saverule("APG_EradicateInfection", comments, table, colours)

    def savePercolateInfection(self):

        comments = """
Percolates any infection to all cells of that particular island.

state 0:  vacuum
state 1:  ON
state 2:  OFF
"""
        table = """
n_states:7
neighborhood:Moore
symmetries:permute

var a={0,1,2,3,4,5,6}
var b={0,1,2,3,4,5,6}
var c={0,1,2,3,4,5,6}
var d={0,1,2,3,4,5,6}
var e={0,1,2,3,4,5,6}
var f={0,1,2,3,4,5,6}
var g={0,1,2,3,4,5,6}
var h={0,1,2,3,4,5,6}
var i={0,1,2,3,4,5,6}

var q={3,4}
var da={2,4,6}
var la={1,3,5}

da,q,b,c,d,e,f,g,h,4
la,q,b,c,d,e,f,g,h,3
"""
        colours = """
0    0    0    0
1    0    0  255
2    0    0  127
3  255    0    0
4  127    0    0
5    0  255    0
6    0  127    0
7  255    0  255
8  127    0  127
"""
        self.saverule("APG_PercolateInfection", comments, table, colours)
        
    def saveExpungeObjects(self):

        comments = """
This removes unwanted monominos, blocks, blinkers and beehives.
It is mandatory that one first runs the rule ClassifyObjects.

Run this for four generations, and observe the population
counts after 0, 1, 2, 3 and 4 generations. This will give the
following data:

number of monominos = p(1) - p(0)
number of blocks = (p(2) - p(1))/4
number of blinkers = (p(3) - p(2))/5
number of beehives = (p(4) - p(3))/8
"""
        table = "n_states:18\n"
        table += "neighborhood:Moore\n"
        table += "symmetries:rotate4reflect\n\n"

        table += self.newvars(["a","b","c","d","e","f","g","h","i"], range(0, 17, 1))

        table += """
# Monomino
6,0,0,0,0,0,0,0,0,0

# Death
6,a,b,c,d,e,f,g,h,0
a,6,b,c,d,e,f,g,h,0

# Block
7,7,7,7,0,0,0,0,0,1
1,1,1,1,0,0,0,0,0,0
1,a,b,c,d,e,f,g,h,7

# Blinker
10,0,0,0,9,9,9,0,0,2
9,9,10,0,0,0,0,0,10,3
2,a,b,c,d,e,f,g,h,10
3,a,b,c,d,e,f,g,h,9
9,2,0,3,0,2,0,3,0,6

# Beehive
7,0,7,8,7,0,0,0,0,1
7,0,0,7,8,8,7,0,0,1
8,7,7,8,7,7,0,7,0,4
4,1,1,4,1,1,0,1,0,5
4,a,b,c,d,e,f,g,h,8
5,5,b,c,d,e,f,g,h,6
5,a,b,c,d,e,f,g,h,15
15,a,b,c,d,e,f,g,h,8
"""

        colours = """
0    0    0    0
1  255  255  255
2  127  127  127
7    0    0  255
8    0    0  127
9  255    0    0
10 127    0    0
11   0  255    0
12   0  127    0
13 255  255    0
14 127  127    0
"""
        self.saverule("APG_ExpungeObjects", comments, table, colours)

    def saveCoalesceObjects(self):

        comments = """
A variant of HistoricalLife which separates a field of ash into
distinct objects.

state 0:  vacuum
state 1:  ON
state 2:  OFF
"""
        table = "n_states:3\n"
        table += "neighborhood:Moore\n"
        
        if self.ruletype: #Outer-totalistic
            table += "symmetries:permute\n\n"
    
            table += self.newvars(["a","b","c","d","e","f","g","h","i"], [0, 1, 2])
            table += self.newvars(["da","db","dc","dd","de","df","dg","dh","di"], [0, 2])
            table += self.newvars(["la","lb","lc","ld","le","lf","lg","lh","li"], [1])
    
            minperc = 10
    
            for i in range(9):
                if (self.bee[i]):
                    if (minperc == 10):
                        minperc = i
                    table += self.scoline("l","d",0,1,i)
                    table += self.scoline("l","d",2,1,i)
                if (self.ess[i]):
                    table += self.scoline("l","d",1,1,i)
    
            table += "\n# Bridge inductors\n"
    
            for i in range(9):
                if (i >= minperc):
                    table += self.scoline("l","d",0,2,i)
    
            table += self.scoline("","",1,2,0)
        else: #Isotropic non-totalistic
            rule1 = open(self.rulepath, "r")
            lines = rule1.read().split("\n")
            lines1 = []
            for i in lines:
                l1 = i.split("\r")
                for j in l1:
                    lines1.append(j)
            rule1.close()
            for q in range(len(lines1)-1):
                if lines1[q].startswith("@TABLE"):
                    lines1 = lines1[q:]
                    break
            vars = []
            for q in range(len(lines1)-1): #Copy symmetries and vars
                i = lines1[q]
                if i[:2] == "sy" or i[:1] == "sy":
                    table += i + "\n\n"
                if i[:2] == "va" or i[:1] == "va":
                    '''table += self.newvar(i[4:5].replace("=", ""), [0, 1, 2])
                    vars.append(i[4:5].replace("=", ""))'''
                if i != "":
                    if i[0] == "0" or i[0] == "1":
                        break
            
            alpha = "abcdefghijklmnopqrstuvwxyz"
            vars2 = []
            '''for i in alpha: 
                if not i in [n[0] for n in vars]: #Create new set of vars for OFF cells
                    table += self.newvars([i + j for j in alpha[:9]], [0, 2])
                    vars2 = [i + j for j in alpha[:9]]
                    break
                    
            for i in alpha: 
                if not i in [n[0] for n in vars] and not i in [n[0] for n in vars2]:
                    for j in range(5-len(vars)):
                        table += self.newvar(i + alpha[j], [0, 1, 2])
                        vars.append(i + alpha[j])
                    break'''
            vars = ["aa", "ab", "ac", "ad", "ae", "af", "ag", "ah"]
            vars2 = ["ba", "bb", "bc", "bd", "be", "bf", "bg", "bh"]
            table += self.newvars(vars, [0, 1, 2])
            table += self.newvars(vars2, [0, 2])
            
            for i in lines1:
                q = i.split("#")[0].replace(" ", "").split(",")
                if len(q[0]) > 1:
                    if len(q) == 1 and (q[0][1] == "0" or q[0][1] == "1"):
                        q = list(q[0])
                if len(q) > 1 and not i.startswith("var"):
                    vn = 0
                    vn2 = 0
                    for j in q[:-1]:
                        if j == "0":
                            table += vars2[vn2]
                            vn2 += 1
                        elif j == "1":
                            table += "1"
                        elif j != "#":
                            table += vars[vn]
                            vn += 1
                        table += ","
                    table += str(2-int(q[len(q)-1]))
                    table += "\n"
                
            for i in range(256): #Get all B3+ rules
                ncells = 0
                for j in range(8):
                    if (i & 2**j) > 0:
                        ncells += 1
                if ncells == 3:
                    q = "0,"
                    vn = 0
                    for j in range(8):
                        if i & 2**j > 0:
                            q += str((i & 2**j)/2**j) + ","
                        else:
                            q += vars[vn] + ","
                            vn += 1
                    q += "2\n"
                    table += q
                
        colours = """
0    0    0    0
1  255  255  255
2  127  127  127
"""
        self.saverule("APG_CoalesceObjects_"+self.alphanumeric, comments, table, colours)
    
    def saveDecayer(self):
    
        comments = """
A multipurpose rule used to assist with decomposition.
"""
        table = """
n_states:9
neighborhood:vonNeumann
symmetries:permute
var a={0,1,2,3,4,5,6,7,8}
var aa=a
var ab=a
var ac=a
8,a,aa,ab,ac,0
7,a,aa,ab,ac,0
6,a,aa,ab,ac,2
5,a,aa,ab,ac,1
4,a,aa,ab,ac,2
3,a,aa,ab,ac,1
2,a,aa,ab,ac,0
1,a,aa,ab,ac,0
0,a,aa,ab,ac,0
"""
        colours = ""
        self.saverule("APG_Decayer", comments, table, colours)
        
    def saveTreeMaker(self):
        
        comments = """
A surprisingly simple rule used to prepare objects for decomposition.
"""

        '''table = """
n_states:3
neighborhood:Moore
symmetries:permute
var a={0,1,2}
var aa=a
var ab=a
var ac=a
var ad=a
var ae=a
var af=a
var ag=a
var b={0,2}
var ba=b
var bb=b
var bc=b
var bd=b
var be=b
var bf=b
var bg=b
0,1,1,1,b,ba,bb,bc,bd,2"""'''
        table = "n_states:3\n"
        table += "neighborhood:Moore\n"
        
        if self.ruletype: #Outer-totalistic
            table += "symmetries:permute\n\n"
    
            table += self.newvars(["da","db","dc","dd","de","df","dg","dh","di"], [0,2])
            table += self.newvars(["la","lb","lc","ld","le","lf","lg","lh","li"], [1])
    
            minperc = 10
    
            for i in range(9):
                if (self.bee[i]):
                    table += self.scoline("l","d",0,2,i)
    
        else: #Isotropic non-totalistic
            rule1 = open(self.rulepath, "r")
            lines = rule1.read().split("\n")
            lines1 = []
            for i in lines:
                l1 = i.split("\r")
                for j in l1:
                    lines1.append(j)
            rule1.close()
            for q in range(len(lines1)-1):
                if lines1[q].startswith("@TABLE"):
                    lines1 = lines1[q:]
                    break
            vars = []
            for q in range(len(lines1)-1): #Copy symmetries and vars
                i = lines1[q]
                if i[:2] == "sy" or i[:1] == "sy":
                    table += i + "\n\n"
                if i[:2] == "va" or i[:1] == "va":
                    '''table += self.newvar(i[4:5].replace("=", ""), [0, 1, 2])
                    vars.append(i[4:5].replace("=", ""))'''
                if i != "":
                    if i[0] == "0" or i[0] == "1":
                        break
            
            alpha = "abcdefghijklmnopqrstuvwxyz"
            vars2 = []
            '''for i in alpha: 
                if not i in [n[0] for n in vars]: #Create new set of vars for OFF cells
                    table += self.newvars([i + j for j in alpha[:9]], [0, 2])
                    vars2 = [i + j for j in alpha[:9]]
                    break
                    
            for i in alpha: 
                if not i in [n[0] for n in vars] and not i in [n[0] for n in vars2]:
                    for j in range(5-len(vars)):
                        table += self.newvar(i + alpha[j], [0, 1, 2])
                        vars.append(i + alpha[j])
                    break'''
            vars = ["aa", "ab", "ac", "ad", "ae", "af", "ag", "ah"]
            vars2 = ["ba", "bb", "bc", "bd", "be", "bf", "bg", "bh"]
            table += self.newvars(vars, [0, 1, 2])
            table += self.newvars(vars2, [0, 2])
            
            for i in lines1:
                q = i.split("#")[0].replace(" ", "").split(",")
                if len(q[0]) > 1:
                    if len(q) == 1 and (q[0][1] == "0" or q[0][1] == "1"):
                        q = list(q[0])
                if len(q) > 1 and not i.startswith("var") and q[0] != "1":
                    vn = 0
                    vn2 = 0
                    for j in q[:-1]:
                        if j == "0":
                            table += vars2[vn2]
                            vn2 += 1
                        elif j == "1":
                            table += "1"
                        elif j != "#":
                            table += ("0",vars[vn])[j!=0]
                            vn += 1
                        table += ","
                    table += "2\n"
                
        colours = """
0    0    0    0
1  255  255  255
2  127  127  127
"""
        self.saverule("APG_TreeMaker_"+self.alphanumeric, comments, table, colours)
    
    def saveClassifyObjects(self):

        comments = """
This passively classifies objects as either still-lifes, p2 oscillators
or higher-period oscillators. It is mandatory that one first runs the
rule CoalesceObjects.

state 0:  vacuum
state 1:  input ON
state 2:  input OFF

state 3:  ON, will die
state 4:  OFF, will remain off
state 5:  ON, will survive
state 6:  OFF, will become alive

state 7:  ON, still-life
state 8:  OFF, still-life

state 9:  ON, p2 oscillator
state 10: OFF, p2 oscillator

state 11: ON, higher-period object
state 12: OFF, higher-period object
"""
        table = "n_states:18\n"
        table += "neighborhood:Moore\n"
        if self.ruletype: #Outer-totalistic
            table += "symmetries:permute\n\n"
    
            table += self.newvars(["a","b","c","d","e","f","g","h","i"], range(0, 17, 1))
            table += self.newvars(["la","lb","lc","ld","le","lf","lg","lh","li"], range(1, 17, 2))
            table += self.newvars(["da","db","dc","dd","de","df","dg","dh","di"], range(0, 17, 2))
            table += self.newvars(["pa","pb","pc","pd","pe","pf","pg","ph","pi"], [0, 3, 4])
            table += self.newvars(["qa","qb","qc","qd","qe","qf","qg","qh","qi"], [5, 6])
    #Serious modifications necessary:
            for i in range(9):
                if (self.bee[i]):
                    table += self.scoline("l","d",2,6,i)
                    table += self.scoline("q","p",3,9,i)
                    table += self.scoline("q","p",4,12,i)
                if (self.ess[i]):
                    table += self.scoline("l","d",1,5,i)
                    table += self.scoline("q","p",5,7,i)
                    table += self.scoline("q","p",6,12,i)
            table += self.scoline("","",2,4,0)
            table += self.scoline("","",1,3,0)
            table += self.scoline("","",5,11,0)
            table += self.scoline("","",3,11,0)
            table += self.scoline("","",4,8,0)
            table += self.scoline("","",6,10,0)
        
        else: #Isotropic non-totalistic
            rule1 = open(self.rulepath, "r")
            lines = rule1.read().split("\n")
            lines1 = []
            for i in lines:
                l1 = i.split("\r")
                for j in l1:
                    lines1.append(j)
            rule1.close()
            for q in range(len(lines1)-1):
                if lines1[q].startswith("@TABLE"):
                    lines1 = lines1[q:]
                    break
                if lines1[0].startswith("@TREE"):
                    g.warn("apgsearch v.0.54+0.1i does not support rule trees")
            vars = []
            for q in range(len(lines1)-1): #Copy symmetries and vars
                i = lines1[q]
                if i[:2] == "sy" or i[:1] == "sy":
                    table += i + "\n\n"
                if i[:2] == "va" or i[:1] == "va":
                    '''table += self.newvar(i[4:5].replace("=", ""), [0, 1, 2, 3, 4, 5, 6])
                    vars.append(i[4:5].replace("=", ""))'''
                if i != "":
                    if i[0] == "0" or i[0] == "1":
                        break
            alpha = "abcdefghijklmnopqrstuvwxyz"
            ovars = []
            '''for i in alpha: 
                if not i in [n[0] for n in vars]: #Create new set of vars for ON cells
                    table += self.newvars([i + j for j in alpha[:9]], [1, 5, 6])
                    ovars = [i + j for j in alpha[:9]]
                    break'''
            
            dvars = []
            
            vars = ["aa", "ab", "ac", "ad", "ae", "af", "ag", "ah"]
            dvars = ["ba", "bb", "bc", "bd", "be", "bf", "bg", "bh"]
            ovars = ["ca", "cb", "cc", "cd", "ce", "cf", "cg", "ch"]
            table += self.newvars(vars, range(7))
            table += self.newvars(dvars, [0, 2, 3, 4])
            table += self.newvars(ovars, [1, 5, 6])
            '''for i in alpha: 
                if not i in [n[0] for n in vars] and not i in [n[0] for n in ovars]: #Create new set of vars for OFF cells
                    table += self.newvars([i + j for j in alpha[:9]], [0, 2, 3, 4])
                    dvars = [i + j for j in alpha[:9]]
                    break
                    
            for i in alpha: 
                if not i in [n[0] for n in vars] and not i in [n[0] for n in ovars] and not i in [n[0] for n in dvars]:
                    for j in range(8-len(vars)):
                        table += self.newvar(i + alpha[j], [0, 1, 2, 3, 4, 5, 6])
                        vars.append(i + alpha[j])
                    break'''
            
            for i in lines1:
                q = i.split("#")[0].replace(" ", "").split(",")
                if len(q[0]) > 1:
                    if len(q) == 1 and (q[0][1] == "0" or q[0][1] == "1"):
                        q = list(q[0])
                if len(q) > 1:
                    vn = 0
                    ovn = 0
                    dvn = 0
                    if q[0] == "0" or q[0] == "1":
                        if q[0] == "0":
                            table += "2"
                        elif q[0] == "1":
                            table += "1"
                        elif q[0] != "#":
                            table += vars[vn]
                            vn += 1
                        table += ","
                        for j in q[1:-1]:
                            if j == "0":
                                table += dvars[dvn]
                                dvn += 1
                            elif j == "1":
                                table += "1"
                            elif j != "#":
                                table += vars[vn]
                                vn += 1
                            table += ","
                        table += str(4-int(q[0])+2*int(q[len(q)-1]))
                        table += "\n"
                    elif not i.startswith("var"): #Line starts with a variable.
                        table += vars[vn] + ","
                        vn += 1
                        for j in q[1:-1]:
                            if j == "0":
                                table += dvars[dvn]
                                dvn += 1
                            elif j == "1":
                                table += "1"
                            elif j != "#":
                                table += vars[vn]
                                vn += 1
                            table += ","
                        table += str(4+2*int(q[len(q)-1]))
                        table += "\n1,"
                        vn = 0
                        for j in q[1:-1]:
                            if j == "0":
                                table += "2"
                            elif j == "1":
                                table += "1"
                            elif j != "#":
                                table += vars[vn]
                                vn += 1
                            table += ","
                        table += str(3+2*int(q[len(q)-1]))
                        table += "\n"
            table += "2," + ",".join(vars[:8]) + ",4\n"
            table += "1," + ",".join(vars[:8]) + ",5\n"
                    
            for i in lines1:
                q = i.split("#")[0].replace(" ", "").split(",")
                if len(q[0]) > 1:
                    if len(q) == 1 and (q[0][1] == "0" or q[0][1] == "1"):
                        q = list(q[0])
                if len(q) > 1:
                    vn = 0
                    ovn = 0
                    dvn = 0
                    if q[0] == "0" or q[0] == "1":
                        table += str(4+2*int(q[0])) + ","
                        for j in q[1:-1]:
                            if j == "0":
                                table += dvars[dvn]
                                dvn += 1
                            elif j == "1":
                                table += ovars[ovn]
                                ovn += 1
                            elif j != "#":
                                table += vars[vn]
                                vn += 1
                            table += ","
                        if q[0] == "0" and q[len(q)-1] == "0":
                            table += "8"
                        if q[0] == "1" and q[len(q)-1] == "0":
                            table += "10"
                        if q[0] == "0" and q[len(q)-1] == "1":
                            table += "12"
                        if q[0] == "1" and q[len(q)-1] == "1":
                            table += "12"
                        table += "\n"
                    elif not i.startswith("var"): #Line starts with a variable.
                        table += "5,"
                        for j in q[1:-1]:
                            if j == "0":
                                table += dvars[dvn]
                                dvn += 1
                            elif j == "1":
                                table += ovars[ovn]
                                ovn += 1
                            elif j != "#":
                                table += vars[vn]
                                vn += 1
                            table += ","
                        if q[len(q)-1] == "0":
                            table += "7"
                        if q[len(q)-1] == "1":
                            table += "11"
                        table += "\n3,"
                        for j in q[1:-1]:
                            if j == "0":
                                table += dvars[dvn]
                                dvn += 1
                            elif j == "1":
                                table += ovars[ovn]
                                ovn += 1
                            elif j != "#":
                                table += vars[vn]
                                vn += 1
                            table += ","
                        if q[len(q)-1] == "0":
                            table += "9"
                        if q[len(q)-1] == "1":
                            table += "11"
                        table += "\n"
                        
            for i in lines1:
                q = i.split("#")[0].replace(" ", "").split(",")
                if len(q[0]) > 1:
                    if len(q) == 1 and (q[0][1] == "0" or q[0][1] == "1"):
                        q = list(q[0])
                if len(q) > 1:
                    vn = 0
                    ovn = 0
                    dvn = 0
                    if q[0] == "0" or q[0] == "1":
                        table += str(3+2*int(q[0])) + ","
                        for j in q[1:-1]:
                            if j == "0":
                                table += dvars[dvn]
                                dvn += 1
                            elif j == "1":
                                table += ovars[ovn]
                                ovn += 1
                            elif j != "#":
                                table += vars[vn]
                                vn += 1
                            table += ","
                        if q[0] == "0" and q[len(q)-1] == "0":
                            table += "11"
                        if q[0] == "1" and q[len(q)-1] == "0":
                            table += "11"
                        if q[0] == "0" and q[len(q)-1] == "1":
                            table += "9"
                        if q[0] == "1" and q[len(q)-1] == "1":
                            table += "7"
                        table += "\n"
                    elif not i.startswith("var"): #Line starts with a variable.
                        table += "6,"
                        for j in q[1:-1]:
                            if j == "0":
                                table += dvars[dvn]
                                dvn += 1
                            elif j == "1":
                                table += ovars[ovn]
                                ovn += 1
                            elif j != "#":
                                table += vars[vn]
                                vn += 1
                            table += ","
                        if q[len(q)-1] == "0":
                            table += "12"
                        if q[len(q)-1] == "1":
                            table += "10"
                        table += "\n4,"
                        for j in q[1:-1]:
                            if j == "0":
                                table += dvars[dvn]
                                dvn += 1
                            elif j == "1":
                                table += ovars[ovn]
                                ovn += 1
                            elif j != "#":
                                table += vars[vn]
                                vn += 1
                            table += ","
                        if q[len(q)-1] == "0":
                            table += "8"
                        if q[len(q)-1] == "1":
                            table += "12"
                        table += "\n"
            table += "4," + ",".join(vars[:8]) + ",8\n"
            table += "3," + ",".join(vars[:8]) + ",11\n"
            table += "6," + ",".join(vars[:8]) + ",12\n"
            table += "5," + ",".join(vars[:8]) + ",7\n"
                        
        colours = """
0    0    0    0
1  255  255  255
2  127  127  127
7    0    0  255
8    0    0  127
9  255    0    0
10 127    0    0
11   0  255    0
12   0  127    0
13 255  255    0
14 127  127    0
"""
        self.saverule("APG_ClassifyObjects_"+self.alphanumeric, comments, table, colours)

    def savePropagateClassifications(self):
        
        comments = """This propagates the result of running ClassifyObjects for two generations.
"""
        
        table = "n_states:18\n"
        table += "neighborhood:Moore\n"
        table += "symmetries:permute\n\n"
    
        table += self.newvars(["a","b","c","d","e","f","g","h","i"], range(0, 17, 1))
        
        table += """
7,11,b,c,d,e,f,g,h,11
7,12,b,c,d,e,f,g,h,11
7,9,b,c,d,e,f,g,h,9
7,10,b,c,d,e,f,g,h,9
8,11,b,c,d,e,f,g,h,12
8,12,b,c,d,e,f,g,h,12
8,9,b,c,d,e,f,g,h,10
8,10,b,c,d,e,f,g,h,10

7,13,b,c,d,e,f,g,h,11
7,14,b,c,d,e,f,g,h,11
8,13,b,c,d,e,f,g,h,14
8,14,b,c,d,e,f,g,h,14
9,13,b,c,d,e,f,g,h,11
9,14,b,c,d,e,f,g,h,11
10,13,b,c,d,e,f,g,h,14
10,14,b,c,d,e,f,g,h,14

9,11,b,c,d,e,f,g,h,11
9,12,b,c,d,e,f,g,h,11
10,11,b,c,d,e,f,g,h,12
10,12,b,c,d,e,f,g,h,12

13,11,b,c,d,e,f,g,h,11
13,12,b,c,d,e,f,g,h,11
14,11,b,c,d,e,f,g,h,12
14,12,b,c,d,e,f,g,h,12
13,9,b,c,d,e,f,g,h,11
14,9,b,c,d,e,f,g,h,12
"""
        colours = """
0    0    0    0
1  255  255  255
2  127  127  127
7    0    0  255
8    0    0  127
9  255    0    0
10 127    0    0
11   0  255    0
12   0  127    0
13 255  255    0
14 127  127    0
"""

        self.saverule("APG_PropagateClassification", comments, table, colours)
        #foo = "" + 2
    def saveContagiousLife(self):

        comments = """
A variant of HistoricalLife used for detecting dependencies between
islands.

state 0:  vacuum
state 1:  ON
state 2:  OFF
"""
        table = "n_states:7\n"
        table += "neighborhood:Moore\n"
        
        if self.ruletype:
            table += "symmetries:permute\n\n"

            table += self.newvars(["a","b","c","d","e","f","g","h","i"], range(0, 7, 1))
            table += self.newvars(["la","lb","lc","ld","le","lf","lg","lh","li"], range(1, 7, 2))
            table += self.newvars(["da","db","dc","dd","de","df","dg","dh","di"], range(0, 7, 2))
            table += self.newvar("p",[3, 4])
            table += self.newvars(["ta","tb","tc","td","te","tf","tg","th","ti"], [3])
            table += self.newvars(["qa","qb","qc","qd","qe","qf","qg","qh","qi"], [0, 1, 2, 4, 5, 6])

            for i in range(9):
                if (self.bee[i]):
                    table += self.scoline("l","d",4,3,i)
                    table += self.scoline("l","d",2,1,i)
                    table += self.scoline("l","d",0,1,i)
                    table += self.scoline("l","d",6,5,i)
                    table += self.scoline("t","q",0,4,i)
                if (self.ess[i]):
                    table += self.scoline("l","d",3,3,i)
                    table += self.scoline("l","d",5,5,i)
                    table += self.scoline("l","d",1,1,i)

            table += "# Default behaviour (death):\n"
            table += self.scoline("","",1,2,0)
            table += self.scoline("","",5,6,0)
            table += self.scoline("","",3,4,0)
        else:
            rule1 = open(self.rulepath, "r")
            lines = rule1.read().split("\n")
            lines1 = []
            for i in lines:
                l1 = i.split("\r")
                for j in l1:
                    lines1.append(j)
            rule1.close()
            for q in range(len(lines1)-1):
                if lines1[q].startswith("@TABLE"):
                    lines1 = lines1[q:]
                    break
            vars = []
            for q in range(len(lines1)-1): #Copy symmetries and vars
                i = lines1[q]
                if i[:2] == "sy" or i[:1] == "sy":
                    table += i + "\n\n"
                if i[:2] == "va" or i[:1] == "va":
                    '''table += self.newvar(i[4:5].replace("=", ""), [0, 1, 2, 3, 4, 5, 6])
                    vars.append(i[4:5].replace("=", ""))'''
                if i != "":
                    if i[0] == "0" or i[0] == "1":
                        break
            alpha = "abcdefghijklmnopqrstuvwxyz"
            ovars = []
            '''for i in alpha: 
                if not i in [n[0] for n in vars]: #Create new set of vars for ON cells
                    table += self.newvars([i + j for j in alpha[:9]], [1, 3, 5])
                    ovars = [i + j for j in alpha[:9]]
                    break'''
            dvars = []
            '''for i in alpha: 
                if not i in [n[0] for n in vars] and not i in [n[0] for n in ovars]: #Create new set of vars for OFF cells
                    table += self.newvars([i + j for j in alpha[:9]], [0, 2, 4, 6])
                    dvars = [i + j for j in alpha[:9]]
                    break
                    
            for i in alpha: 
                if not i in [n[0] for n in vars] and not i in [n[0] for n in ovars] and not i in [n[0] for n in dvars]:
                    for j in range(8-len(vars)):
                        table += self.newvar(i + alpha[j], [0, 1, 2, 3, 4, 5, 6])
                        vars.append(i + alpha[j])
                    break'''
            
            qvars = []
            '''for i in alpha:
                if not i in [n[0] for n in vars] and not i in [n[0] for n in ovars] and not i in [n[0] for n in dvars]:
                    table += self.newvars([i + j for j in alpha[:9]], [0, 1, 2, 4, 5, 6])
                    qvars = [i + j for j in alpha[:9]]
                    break'''
                    
            vars = ["aa", "ab", "ac", "ad", "ae", "af", "ag", "ah"]
            dvars = ["ba", "bb", "bc", "bd", "be", "bf", "bg", "bh"]
            ovars = ["ca", "cb", "cc", "cd", "ce", "cf", "cg", "ch"]
            qvars = ["da", "db", "dc", "dd", "de", "df", "dg", "dh"]
            table += self.newvars(vars, range(7))
            table += self.newvars(dvars, [0, 2, 4, 6])
            table += self.newvars(ovars, [1, 3, 5])
            table += self.newvars(qvars, [0, 1, 2, 4, 5, 6])
            
            for i in lines1:
                q = i.split("#")[0].replace(" ", "").split(",")
                if len(q[0]) > 1:
                    if len(q) == 1 and (q[0][1] == "0" or q[0][1] == "1"):
                        q = list(q[0])
                if len(q) > 1 and not i.startswith("var"):
                    vn = 0
                    ovn = 0
                    dvn = 0
                    qvn = 0
                    table += str(2-int(q[0])) + ","
                    for j in q[1:-1]:
                        if j == "0":
                            table += dvars[dvn]
                            dvn += 1
                        elif j == "1":
                            table += ovars[ovn]
                            ovn += 1
                        elif j != "#":
                            table += vars[vn]
                            vn += 1
                        table += ","
                    if q[len(q)-1] == "0":
                        table += "2"
                    if q[len(q)-1] == "1":
                        table += "1"
                    table += "\n"
                    vn = 0
                    ovn = 0
                    dvn = 0
                    qvn = 0
                    table += str(4-int(q[0])) + ","
                    for j in q[1:-1]:
                        if j == "0":
                            table += dvars[dvn]
                            dvn += 1
                        elif j == "1":
                            table += ovars[ovn]
                            ovn += 1
                        elif j != "#":
                            table += vars[vn]
                            vn += 1
                        table += ","
                    if q[len(q)-1] == "0":
                        table += "4"
                    if q[len(q)-1] == "1":
                        table += "3"
                    table += "\n"
                    vn = 0
                    ovn = 0
                    dvn = 0
                    qvn = 0
                    table += str(6-int(q[0])) + ","
                    for j in q[1:-1]:
                        if j == "0":
                            table += dvars[dvn]
                            dvn += 1
                        elif j == "1":
                            table += ovars[ovn]
                            ovn += 1
                        elif j != "#":
                            table += vars[vn]
                            vn += 1
                        table += ","
                    if q[len(q)-1] == "0":
                        table += "6"
                    if q[len(q)-1] == "1":
                        table += "5"
                    table += "\n"
                    
            for i in lines1:
                q = i.split("#")[0].replace(" ", "").split(",")
                if len(q[0]) > 1:
                    if len(q) == 1 and (q[0][1] == "0" or q[0][1] == "1"):
                        q = list(q[0])
                if len(q) > 1:
                    vn = 0
                    ovn = 0
                    dvn = 0
                    qvn = 0
                    if q[0] == "0":
                        table += "0,"
                        for j in q[1:-1]:
                            if j == "0":
                                table += dvars[dvn]
                                dvn += 1
                            elif j == "1":
                                table += ovars[ovn]
                                ovn += 1
                            elif j != "#":
                                table += vars[vn]
                                vn += 1
                            table += ","
                        if q[len(q)-1] == "1":
                            table += "1"
                        else:
                            table += "0"
                        table += "\n"
                        
            for i in lines1:
                q = i.split("#")[0].replace(" ", "").split(",")
                if len(q[0]) > 1:
                    if len(q) == 1 and (q[0][1] == "0" or q[0][1] == "1"):
                        q = list(q[0])
                if len(q) > 1:
                    vn = 0
                    ovn = 0
                    dvn = 0
                    qvn = 0
                    if q[0] == "0":
                        table += "0,"
                        for j in q[1:-1]:
                            if j == "0":
                                table += qvars[qvn]
                                qvn += 1
                            elif j == "1":
                                table += "3"
                            elif j != "#":
                                table += vars[vn]
                                vn += 1
                            table += ","
                        if q[len(q)-1] == "1":
                            table += "4"
                        else:
                            table += "0"
                        table += "\n"

        colours = """
0    0    0    0
1    0    0  255
2    0    0  127
3  255    0    0
4  127    0    0
5    0  255    0
6    0  127    0
7  255    0  255
8  127    0  127
"""
        self.saverule("APG_ContagiousLife_"+self.alphanumeric, comments, table, colours)


class Soup:

    def __init__(self):

        # The rule generator:
        self.rg = RuleGenerator()

        # Should we skip error-correction:
        self.skipErrorCorrection = False

        # A dict mapping binary representations of small possibly-pseudo-objects
        # to their equivalent canonised representation.
        #
        # This is many-to-one, as (for example) all of these will map to
        # the same pseudo-object (namely the beacon on block):
        #
        # ..**.**  ..**.**  **.....                           **.....
        # ..**.**  ...*.**  **.....                           *......
        # **.....  *......  ..**...                           ...*.**
        # **.....  **.....  ..**... [...12 others omitted...] ..**.**
        # .......  .......  .......                           .......
        # .......  .......  ..**...                           .......
        # .......  .......  ..**...                           .......
        #
        # The first few soups are much slower to process, as objects are being
        # entered into the cache.
        self.cache = {}

        # A dict to store memoized decompositions of possibly-pseudo-objects
        # into constituent parts. This is initialised with the unique minimal
        # pseudo-still-life (two blocks on lock) that cannot be automatically
        # separated by the routine pseudo_bangbang(). Any larger objects are
        # ambiguous, such as this one:
        #
        #     *
        #    * * **
        #     ** **
        #
        #    * *** *
        #    ** * **
        #
        # Is it a (block on (lock on boat)) or ((block on lock) on boat)?
        # Ahh, the joys of non-associativity.
        #
        # See https://paradise.caltech.edu/~cook/Workshop/CAs/2DOutTot/Life/StillLife/StillLifeTheory.html
        self.decompositions = {"xs18_3pq3qp3": ["xs14_3123qp3", "xs4_33"]}
        self.apgcodetorle = {}#Stores the corresponding rles for apgcodes, enabling the census to throw out faulty apgcodes.
        
        # A dict of objects in the form {"identifier": ("common name", points)}
        #
        # As a rough heuristic, an object is worth 15 + log2(n) points if it
        # is n times rarer than the pentadecathlon.
        #
        # Still-lifes are limited to 10 points.
        # p2 oscillators are limited to 20 points.
        # p3 and p4 oscillators are limited to 30 points.
        self.commonnames = {"xp3_co9nas0san9oczgoldlo0oldlogz1047210127401": ("pulsar", 8),
                       "xp15_4r4z4r4": ("pentadecathlon", 15),
                       "xp2_2a54": ("clock", 16),
                       "xp2_31ago": ("bipole", 17),
                       "xp2_0g0k053z32": ("quadpole", 18),
                       "xp2_g8gid1e8z1226": ("great on-off", 19),
                       "xp2_rhewehr": ("spark coil", 19),
                       "xp8_gk2gb3z11": ("figure-8", 20),
                       "xp4_37bkic": ("mold", 21),
                       "xp2_31a08zy0123cko": ("quadpole on ship", 20),
                       "xp2_g0k053z11": ("tripole", 20),
                       "xp4_ssj3744zw3": ("mazing", 23),
                       "xp8_g3jgz1ut": ("blocker", 24),
                       "xp3_695qc8zx33": ("jam", 24),
                       "xp30_w33z8kqrqk8zzzw33": ("cis-queen-bee-shuttle", 24),
                       "xp30_w33z8kqrqk8zzzx33": ("trans-queen-bee-shuttle", 24),
                       "xp4_8eh5e0e5he8z178a707a871": ("cloverleaf", 25),
                       "xp5_idiidiz01w1": ("octagon II", 26),
                       "xp6_ccb7w66z066": ("unix", 26),
                       "xp14_j9d0d9j": ("tumbler", 27),
                       "xp3_025qzrq221": ("trans-tub-eater", 28),
                       "xp3_4hh186z07": ("caterer", 29),
                       "xp3_025qz32qq1": ("cis-tub-eater", 30),
                       "xp8_wgovnz234z33": ("Tim Coe's p8", 31),
                       "xp5_3pmwmp3zx11": ("fumarole", 33),
                       "xp46_330279cx1aad3y833zx4e93x855bc": ("cis-twin-bees-shuttle", 35),
                       "xp46_330279cx1aad3zx4e93x855bcy8cc": ("trans-twin-bees-shuttle", 35),
                       "yl144_1_16_afb5f3db909e60548f086e22ee3353ac": ("block-laying switch engine", 16),
                       "yl384_1_59_7aeb1999980c43b4945fb7fcdb023326": ("glider-producing switch engine", 17),
                       "xp10_9hr": ("[HighLife] p10", 6),
                       "xp7_13090c8": ("[HighLife] p7", 9),
                       "xq48_07z8ca7zy1e531": ("[HighLife] bomber", 9),
                       "xq4_153": ("glider", 0),
                       "xq4_6frc": ("lightweight spaceship", 7),
                       "xq4_27dee6": ("middleweight spaceship", 9),
                       "xq4_27deee6": ("heavyweight spaceship", 12),
                       "xq7_3nw17862z6952": ("loafer", 999),
                       "xs8_rr": ("bi-block", 0),
                       "xs10_660696": ("block on beehive", 0),
                       "xs9_253033": ("block on boat", 0),
                       "xs12_6960696": ("bi-beehive", 0),
                       "xs11_2596066": ("block on loaf", 0),
                       "xp2_rbzw23": ("block on beacon", 0),
                       "xs10_2530352": ("cis bi-boat", 0),
                       "xs12_6606996": ("block on pond", 0),
                       "xs12_3560653": ("cis bi-ship", 0),
                       "xs11_2560696": ("boat on beehive", 0),
                       "xs10_330356": ("block on ship", 0),
                       "xs14_259606952": ("cis loaf on loaf", 0),
                       "xs13_25960696": ("beehive on loaf", 0),
                       "xs14_69606996": ("beehive on pond", 0),
                       "xs10_25606a4": ("trans bi-boat", 0),
                       "xs12_25606952": ("cis boat on loaf", 0),
                       "xs11_25ac0cc": ("block on long boat", 0),
                       "xs12_rrz66": ("tri-block", 0),
                       "xs13_25ac0cic": ("beehive on long boat", 0),
                       "xs16_699606996": ("pond on pond", 0),
                       "xp2_2530318c": ("cis boat on beacon", 0),
                       "xs12_3560696": ("beehive on ship", 0),
                       "xs16_rr0rr": ("2x2 block array", 0),
                       "xs11_33032ac": ("block on eater tail", 0),
                       "xs14_2596069a4": ("trans loaf on loaf", 0),
                       "xs14_35606996": ("ship on pond", 0),
                       "xs15_259606996": ("loaf on pond", 0),
                       "xp2_318c0cic": ("beehive on beacon", 0),
                       "xs10_33039c": ("trans block on aircraft carrier", 0),
                       "xs12_253035a4": ("cis boat on long boat", 0),
                       "xp2_7": ("blinker", 0),
                       "xs4_33": ("block", 0),
                       "xs4_252": ("tub", 0),
                       "xs5_253": ("boat", 0),
                       "xs6_bd": ("snake", 0),
                       "xs6_356": ("ship", 0),
                       "xs6_696": ("beehive", 0),
                       "xs6_25a4": ("barge", 0),
                       "xs6_39c": ("carrier", 0),
                       "xp2_7e": ("toad", 0),
                       "xp2_318c": ("beacon", 0),
                       "xs7_3lo": ("long snake", 0),
                       "xs7_25ac": ("long boat", 0),
                       "xs7_178c": ("eater", 0),
                       "xs7_2596": ("loaf", 0),
                       "xs8_178k8": ("tub with tail", 0),
                       "xs8_32qk": ("hook with tail", 0),
                       "xs8_69ic": ("mango", 0),
                       "xs8_6996": ("pond", 0),
                       "xs8_25ak8": ("long barge", 0),
                       "xs8_3pm": ("shillelagh", 0),
                       "xs8_312ko": ("canoe", 0),
                       "xs8_31248c": ("very long snake", 0),
                       "xs8_35ac": ("long ship", 0),
                       "xs12_g8o653z11": ("ship-tie", 0),
                       "xs14_g88m952z121": ("half-bakery", 0),
                       "xs14_69bqic": ("paperclip", 0),
                       "xs9_31ego": ("integral sign", 0),
                       "xs10_g8o652z01": ("boat-tie", 0),
                       "xs14_g88b96z123": ("big s", 0),
                       "xs16_g88m996z1221": ("bipond", 0),
                       "xs12_raar": ("table on table", 0),
                       "xs9_4aar": ("hat", 0),
                       "xs10_35ako": ("very long ship", 0),
                       "xs9_178ko": ("trans boat with tail", 0),
                       "xs15_354cgc453": ("moose antlers", 0),
                       "xs14_6970796": ("cis-mirrored bun", 0),
                       "xs10_32qr": ("block on table", 0),
                       "xs16_j1u0696z11": ("beehive on dock", 0),
                       "xs14_j1u066z11": ("block on dock", 0),
                       "xs11_g8o652z11": ("boat tie ship", 0),
                       "xs9_25ako": ("very long boat", 0),
                       "xs16_69egmiczx1": ("scorpion", 0),
                       "xs18_rhe0ehr": ("dead spark coil", 0),
                       "xs17_2ege1ege2": ("twin hat", 0),
                       "xs10_178kk8": ("beehive with tail", 0),
                       "xs10_69ar": ("loop", 0),
                       "xs14_69bo8a6": ("fourteener", 0),
                       "xs14_39e0e93": ("cis mirrored bookends", 0),
                       "xs9_178kc": ("cis boat with tail", 0),
                       "xs12_330f96": ("block and cap", 0),
                       "xs10_358gkc": ("10.003",0),
                       "xs12_330fho": ("trans block and long bookend", 0),
                       "xs10_g0s252z11": ("prodigal sign", 0),
                       "xs11_g0s453z11": ("elevener", 0),
                       "xs14_6is079c": ("cis-rotated hook", 0),
                       "xs14_69e0eic": ("trans-mirrored bun", 0),
                       "xs11_ggm952z1": ("trans loaf with tail", 0),
                       "xs15_j1u06a4z11": ("cis boat and dock", 0),
                       "xs20_3lkkl3z32w23": ("mirrored dock", 0),
                       "xs12_178br": ("12.003",0),
                       "xs12_3hu066": ("cis block and longhook", 0),
                       "xs12_178c453": ("eater with nine", 0),
                       "xs10_0drz32": ("broken snake", 0),
                       "xs9_312453": ("long shillelagh", 0),
                       "xs10_3215ac": ("boat with long tail", 0),
                       "xs14_39e0e96": ("cis-hook and R-bee", 0),
                       "xs13_g88m96z121": ("beehive at loaf", 0),
                       "xs14_39e0eic": ("trans hook and R-bee", 0),
                       "xs10_3542ac": ("S-ten", 0),
                       "xs15_259e0eic": ("trans R-bee and R-loaf", 0),
                       "xs11_178jd": ("11-loop", 0),
                       "xs9_25a84c": ("tub with long tail", 0),
                       "xs15_3lkm96z01": ("bee-hat", 0),
                       "xs14_g8o0e96z121": ("cis-rotated R-bee", 0),
                       "xs13_69e0mq": ("R-bee and snake", 0),
                       "xs11_69lic": ("11.003", 0),
                       "xs12_6960ui": ("beehive and table", 0),
                       "xs16_259e0e952": ("cis-mirrored R-loaf", 0),
                       "xs10_1784ko": ("8-snake-eater", 0),
                       "xs13_4a960ui": ("ortho loaf and table", 0),
                       "xs9_g0g853z11": ("long canoe", 0),
                       "xs18_69is0si96": ("[cis-mirrored R-mango]", 0),
                       "xs11_178kic": ("cis loaf with tail", 0),
                       "xs16_69bob96": ("symmetric scorpion", 0),
                       "xs13_0g8o653z121": ("longboat on ship", 0),
                       "xs12_o4q552z01": ("beehive at beehive", 0),
                       "xs10_ggka52z1": ("trans barge with tail", 0),
                       "xs12_256o8a6": ("eater on boat", 0),
                       "xs14_6960uic": ("beehive with cap", 0),
                       "xs12_2egm93": ("snorkel loop", 0),
                       "xs12_2egm96": ("beehive bend tail", 0),
                       "xs11_g0s253z11": ("trans boat with nine", 0),
                       "xs15_3lk453z121": ("trans boat and dock", 0),
                       "xs19_69icw8ozxdd11": ("[mango with block on dock]", 0),
                       "xs13_2530f96": ("[cis boat and cap]", 0),
                       "xs11_2530f9": ("cis boat and table", 0),
                       "xs14_4a9m88gzx121": ("[bi-loaf2]", 0),
                       "xs11_ggka53z1": ("trans longboat with tail", 0),
                       "xs18_2egm9a4zx346": ("[loaf eater tail]", 0),
                       "xs15_4a9raic": ("[15-bent-paperclip]", 0),
                       "xs11_3586246": ("[11-snake]",0),
                       "xs11_178b52": ("[11-boat wrap tail]", 0),
                       "xs14_08u1e8z321": ("[hat join hook]", 0),
                       "xs14_g4s079cz11": ("[cis-mirrored offset hooks]", 0),
                       "xs13_31egma4": ("[13-boat wrap eater]", 0),
                       "xs14_69960ui": ("pond and table", 0),
                       "xs13_255q8a6": ("[eater tie beehive]", 0),
                       "xs15_09v0ccz321": ("[hook join table and block]",0)}

        # First soup to contain a particular object:
        self.alloccur = {}

        # A tally of objects that have occurred during this run of apgsearch:
        self.objectcounts = {}

        # Any soups with positive scores, and the number of points.
        self.soupscores = {}

        # Temporary list of unidentified objects:
        self.unids = []

        # Things like glider guns and large oscillators belong here:
        self.superunids = []
        self.gridsize = 0
        self.resets = 0

        # For profiling purposes:
        self.qlifetime = 0.0
        self.ruletime = 0.0
        self.gridtime = 0.0

    # Increment object count by given value:
    def incobject(self, obj, incval):
        if (incval > 0):
            if obj in self.objectcounts:
                self.objectcounts[obj] = self.objectcounts[obj] + incval
            else:
                self.objectcounts[obj] = incval

    # Increment soup score by given value:
    def awardpoints(self, soupid, incval):
        if (incval > 0):
            if soupid in self.soupscores:
                self.soupscores[soupid] = self.soupscores[soupid] + incval
            else:
                self.soupscores[soupid] = incval

    # Increment soup score by appropriate value:
    def awardpoints2(self, soupid, obj):

        # Record the occurrence of this object:
        if (obj in self.alloccur):
            if (len(self.alloccur[obj]) < 10):
                if (soupid not in self.alloccur[obj]):
                    self.alloccur[obj] += [soupid]
        else:
            self.alloccur[obj] = [soupid]
        
        if obj in self.commonnames:
            self.awardpoints(soupid, self.commonnames[obj][1])
        elif (obj[0] == 'x'):
            prefix = obj.split('_')[0]
            prenum = int(float(prefix[2:].strip('.0')))
            if (obj[1] == 's'):
                self.awardpoints(soupid, min(prenum, 20)) # for still-lifes, award one point per constituent cell (max 20)
            elif (obj[1] == 'p'):
                if (prenum == 2):
                    self.awardpoints(soupid, 20) # p2 oscillators are limited to 20 points
                elif ((prenum == 3) | (prenum == 4)):
                    self.awardpoints(soupid, 30) # p3 and p4 oscillators are limited to 30 points
                else:
                    self.awardpoints(soupid, 40)
            else:
                self.awardpoints(soupid, 50)
        else:
            self.awardpoints(soupid, 60)
    def verifyobj(self, objname):
        #Function written by me, PK22, in response to erroneous objects being uploaded.
        #It checks still lifes, oscillators, and spaceships, and sees if they are the same after one full period.
        #Testing suggests it takes around 7 milliseconds per generation the pattern is run through,
        #so for a typical Pseudo_C1_Test haul, it takes ~330*7 = 2310 milliseconds, which is a little long,
        #but census safety takes priority over performance.
        if (objname[0] == 'x'):
            # Canonised objects are at most 40-by-40:
            rledata = ''
            # https://ferkeltongs.livejournal.com/15837.html
            compact = objname.split('_')[1] + "z"
            i = 0
            strip = []
            while (i < len(compact)):
                c = ord2(compact[i])
                if (c >= 0):
                    if (c < 32):
                        # Conventional character:
                        strip.append(c)
                    else:
                        if (c == 35):
                            # End of line:
                            if (len(strip) == 0):
                                strip.append(0)
                            for j in range(5):
                                for d in strip:
                                    if ((d & (1 << j)) > 0):
                                        rledata += "o"
                                    else:
                                        rledata += "b"
                                rledata += "$\n"
                            strip = []
                        else:
                            # Multispace character:
                            strip.append(0)
                            strip.append(0)
                            if (c >= 33):
                                strip.append(0)
                            if (c == 34):
                                strip.append(0)
                                i += 1
                                d = ord2(compact[i])
                                for j in range(d):
                                    strip.append(0)
                i += 1
            # End of pattern representation:
            rledata += "!"
            g.new('Verifying objects')
            g.setrule(self.rg.slashed)
            g.putcells(g.parse(rledata), 0, 0)
            period = 0
            if objname[0:2] == 'xs':
                period = 1
            else:
                period = int(objname[2:objname.find('_')])
            if g.getpop() != '0':
                startpattern = g.hash(g.getrect())
            else:
                startpattern = 'fbudnfiunfsnjfnsjfs'
            g.run(period)
            if g.getpop() != '0':
                endpattern = g.hash(g.getrect())
            else:
                endpattern = 'fbudnfiunfsnjfnsfsadsaasdsadadajfs'
            if not startpattern == endpattern:
                g.warn(objname)
            return startpattern == endpattern
        else:
            return True
    # Assuming the pattern has stabilised, perform a census:
    def census(self, stepsize):

        g.setrule("APG_CoalesceObjects_" + self.rg.alphanumeric)
        g.setbase(2)
        g.setstep(stepsize)
        g.step()

        # apgsearch theoretically supports up to 2^14 rules, whereas the Guy
        # glider is only stable in 2^8 rules. Ensure that this is one of these
        # rules by doing some basic Boolean arithmetic.
        #
        # This should be parsed as `gliders exist', not `glider sexist':
        glidersexist = self.rg.ess[2] & self.rg.ess[3] & (not self.rg.ess[1]) & (not self.rg.ess[4])
        glidersexist = glidersexist & (not (self.rg.bee[4] | self.rg.bee[5]))

        if (glidersexist):
            g.setrule("APG_IdentifyGliders")
            g.setbase(2)
            g.setstep(2)
            g.step()

        g.setrule("APG_ClassifyObjects_" + self.rg.alphanumeric)
        g.setbase(2)
        g.setstep(max(8, stepsize))
        g.step()

        # Only do this if we have an infinite-growth pattern:
        if (stepsize > 8):
            g.setrule("APG_HandlePlumesCorrected")
            g.setbase(2)
            g.setstep(1)
            g.step()
            g.setrule("APG_ClassifyObjects_" + self.rg.alphanumeric)
            g.setstep(stepsize)
            g.step()

        # Remove any gliders:
        if (glidersexist):
            g.setrule("APG_ExpungeGliders")
            g.run(1)
            pop5 = int(g.getpop())
            g.run(1)
            pop6 = int(g.getpop())
            self.incobject("xq4_153", int((pop5 - pop6)/5))

        # Remove any blocks, blinkers and beehives:
        g.setrule("APG_ExpungeObjects")
        pop0 = int(g.getpop())
        g.run(1)
        pop1 = int(g.getpop())
        g.run(1)
        pop2 = int(g.getpop())
        g.run(1)
        pop3 = int(g.getpop())
        g.run(1)
        pop4 = int(g.getpop())

        # Dots, Blocks, blinkers and beehives removed by ExpungeObjects:
        self.incobject("xs1_1", int((pop0-pop1)))
        self.incobject("xs4_33", int((pop1-pop2)/4))
        self.incobject("xp2_7", int((pop2-pop3)/5))
        self.incobject("xs6_696", int((pop3-pop4)/8))

    # Removes an object incident with (ix, iy) and returns the cell list:
    def grabobj(self, ix, iy):

        allcells = [ix, iy, g.getcell(ix, iy)]
        g.setcell(ix, iy, 0)
        livecells = []
        deadcells = []

        marker = 0
        ll = 3

        while (marker < ll):
            x = allcells[marker]
            y = allcells[marker+1]
            z = allcells[marker+2]
            marker += 3

            if ((z % 2) == 1):
                livecells.append(x)
                livecells.append(y)
            else:
                deadcells.append(x)
                deadcells.append(y)

            for nx in range(x - 1, x + 2):
                for ny in range(y - 1, y + 2):

                    nz = g.getcell(nx, ny)
                    if (nz > 0):
                        allcells.append(nx)
                        allcells.append(ny)
                        allcells.append(nz)
                        g.setcell(nx, ny, 0)
                        ll += 3

        return livecells

    # Command to Grab, Remove and IDentify an OBJect:
    def gridobj(self, ix, iy, gsize, gspacing, pos):

        allcells = [ix, iy, g.getcell(ix, iy)]
        g.setcell(ix, iy, 0)
        livecells = []
        deadcells = []

        # This tacitly assumes the object is smaller than 1000-by-1000.
        # But this is okay, since it is only used by the routing logic.
        dleft = ix + 1000
        dright = ix - 1000
        dtop = iy + 1000
        dbottom = iy - 1000

        lleft = ix + 1000
        lright = ix - 1000
        ltop = iy + 1000
        lbottom = iy - 1000

        lpop = 0
        dpop = 0

        marker = 0
        ll = 3

        while (marker < ll):
            x = allcells[marker]
            y = allcells[marker+1]
            z = allcells[marker+2]
            marker += 3

            if ((z % 2) == 1):
                livecells.append(x)
                livecells.append(y)
                lleft = min(lleft, x)
                lright = max(lright, x)
                ltop = min(ltop, y)
                lbottom = max(lbottom, y)
                lpop += 1
            else:
                deadcells.append(x)
                deadcells.append(y)
                dleft = min(dleft, x)
                dright = max(dright, x)
                dtop = min(dtop, y)
                dbottom = max(dbottom, y)
                dpop += 1

            for nx in range(x - 1, x + 2):
                for ny in range(y - 1, y + 2):

                    nz = g.getcell(nx, ny)
                    if (nz > 0):
                        allcells.append(nx)
                        allcells.append(ny)
                        allcells.append(nz)
                        g.setcell(nx, ny, 0)
                        ll += 3

        lwidth = max(0, 1 + lright - lleft)
        lheight = max(0, 1 + lbottom - ltop)
        dwidth = max(0, 1 + dright - dleft)
        dheight = max(0, 1 + dbottom - dtop)

        llength = max(lwidth, lheight)
        lbreadth = min(lwidth, lheight)
        dlength = max(dwidth, dheight)
        dbreadth = min(dwidth, dheight)

        self.gridsize = max(self.gridsize, llength)

        objid = "unidentified"
        bitstring = 0

        if (lpop == 0):
            objid = "nothing"
        else:
            if ((lwidth <= 7) & (lheight <= 7)):
                for i in range(0, lpop*2, 2):
                    bitstring += (1 << ((livecells[i] - lleft) + 7*(livecells[i + 1] - ltop)))

                if bitstring in self.cache:
                    objid = self.cache[bitstring]

        if (objid == "unidentified"):
            # This has passed through the routing logic without being identified,
            # so save it in a temporary list for later identification:
            self.unids.append(bitstring)
            self.unids.append(livecells)
            self.unids.append(lleft)
            self.unids.append(ltop)
        elif (objid != "nothing"):
            # The object is non-empty, so add it to the census:
            ux = int(0.5 + float(lleft)/float(gspacing))
            uy = int(0.5 + float(ltop)/float(gspacing))
            soupid = ux + (uy * gsize) + pos

            # Check whether the cached object is in the set of decompositions
            # (this is usually the case, unless for example it is a high-period
            # albeit small spaceship):
            if objid in self.decompositions:            
                for comp in self.decompositions[objid]:
                    self.incobject(comp, 1)
                    self.awardpoints2(soupid, comp)
            else:
                self.incobject(objid, 1)
                self.awardpoints2(soupid, objid)


    # Tests for population periodicity:
    def naivestab(self, period, security, length):

        depth = 0
        prevpop = 0
        for i in range(length):
            g.run(period)
            currpop = int(g.getpop())
            if (currpop == prevpop):
                depth += 1
            else:
                depth = 0
            prevpop = currpop
            if (depth == security):
                # Population is periodic.
                return True

        return False

    # This should catch most short-lived soups with few gliders produced:
    def naivestab2(self, period, length):

        for i in range(length):
            r = g.getrect()
            if (len(r) == 0):
                return True
            pop0 = int(g.getpop())
            g.run(period)
            hash1 = g.hash(r)
            pop1 = int(g.getpop())
            g.run(period)
            hash2 = g.hash(r)
            pop2 = int(g.getpop())

            if ((hash1 == hash2) & (pop0 == pop1) & (pop1 == pop2)):

                if (g.getrect() == r):
                    return True
                
                g.run((2*int(max(r[2], r[3])/period)+1)*period)
                hash3 = g.hash(r)
                pop3 = int(g.getpop())
                if ((hash2 == hash3) & (pop2 == pop3)):
                    return True

        return False
            
    # Runs a pattern until stabilisation with a 99.99996% success rate.
    # False positives are handled by a later error-correction stage.
    def stabilise3(self):

        # Phase I of stabilisation detection, designed to weed out patterns
        # that stabilise into a cluster of low-period oscillators within
        # about 6000 generations.

        if (self.naivestab2(12, 10)):
            return 4;

        if (self.naivestab(12, 30, 200)):
            return 4;

        if (self.naivestab(30, 30, 200)):
            return 5;

        # Phase II of stabilisation detection, which is much more rigorous
        # and based on oscar.py.

        # Should be sufficient:
        prect = [-2000, -2000, 4000, 4000]

        # initialize lists
        hashlist = []        # for pattern hash values
        genlist = []         # corresponding generation counts

        for j in range(4000):

            g.run(30)

            h = g.hash(prect)

            # determine where to insert h into hashlist
            pos = 0
            listlen = len(hashlist)
            while pos < listlen:
                if h > hashlist[pos]:
                    pos += 1
                elif h < hashlist[pos]:
                    # shorten lists and append info below
                    del hashlist[pos : listlen]
                    del genlist[pos : listlen]
                    break
                else:
                    period = (int(g.getgen()) - genlist[pos])

                    prevpop = g.getpop()

                    for i in range(20):
                        g.run(period)
                        currpop = g.getpop()
                        if (currpop != prevpop):
                            period = max(period, 4000)
                            break
                        prevpop = currpop
                        
                    return max(1 + int(math.log(period, 2)),3)

            hashlist.insert(pos, h)
            genlist.insert(pos, int(g.getgen()))

        g.setalgo("HashLife")
        g.setrule(self.rg.slashed)
        g.setbase(2)
        g.setstep(16)
        g.step()
        stepsize = 12
        g.setalgo("QuickLife")
        g.setrule(self.rg.slashed)

        return 12

    # Differs from oscar.py in that it detects absolute cycles, not eventual cycles.
    def bijoscar(self, maxsteps):

        initpop = int(g.getpop())
        initrect = g.getrect()
        if (len(initrect) == 0):
            return 0
        inithash = g.hash(initrect)

        for i in range(maxsteps):

            g.run(1)

            if (int(g.getpop()) == initpop):

                prect = g.getrect()
                phash = g.hash(prect)

                if (phash == inithash):

                    period = i + 1

                    if (prect == initrect):
                        return period
                    else:
                        return -period
        return -1

    # For a non-moving unidentified object, we check the dictionary of
    # memoized decompositions of possibly-pseudo-objects. If the object is
    # not already in the dictionary, it will be memoized.
    #
    # Low-period spaceships are also separated by this routine, although
    # this is less important now that there is a more bespoke prodecure
    # to handle disjoint unions of standard spaceships.
    #
    # @param moving  a bool which specifies whether the object is moving
    def enter_unid(self, unidname, soupid, moving):

        if not(unidname in self.decompositions):
            if not self.pseudo:
                # Separate into pure components:
                if (moving):
                    g.setrule("APG_CoalesceObjects_" + self.rg.alphanumeric)
                    g.setbase(2)
                    g.setstep(3)
                    g.step()
                else:
                    pseudo_bangbang(self.rg.alphanumeric)

                listoflists = [] # which incidentally don't contain themselves.

                # Someone who plays the celllo:
                celllist = g.join(g.getcells(g.getrect()), [0])

                for i in range(0, len(celllist)-1, 3):
                    if (g.getcell(celllist[i], celllist[i+1]) != 0):
                        livecells = self.grabobj(celllist[i], celllist[i+1])
                        if (len(livecells) > 0):
                            listoflists.append(livecells)

                listofobjs = []
                for livecells in listoflists:

                    g.new("Subcomponent")
                    g.setalgo("QuickLife")
                    g.setrule(self.rg.slashed)
                    g.putcells(livecells)
                    period = self.bijoscar(1000)
                    canonised = canonise(abs(period))
                    if (period < 0):
                        listofobjs.append("xq"+str(0-period)+"_"+canonised)
                    elif (period == 1):
                        listofobjs.append("xs"+str(int(len(livecells)/2))+"_"+canonised)
                    else:
                        listofobjs.append("xp"+str(period)+"_"+canonised)
                self.decompositions[unidname] = listofobjs
            else:
                self.decompositions[unidname] = [unidname]
                #This means that all pseudo-objects will be decomposed into themselves.

        # Actually add to the census:
        for comp in self.decompositions[unidname]:
            self.incobject(comp, 1)
            self.awardpoints2(soupid, comp)

    # This function has lots of arguments (hence the name):
    #
    # @param gsize     the square-root of the number of soups per page
    # @param gspacing  the minimum distance between centres of soups
    # @param ashes     a list of cell lists
    # @param stepsize  binary logarithm of amount of time to coalesce objects
    # @param intergen  binary logarithm of amount of time to run HashLife
    # @param pos       the index of the first soup on the page
    def teenager(self, gsize, gspacing, ashes, stepsize, intergen, pos):

        # For error-correction:
        if (intergen > 0):
            g.setalgo("HashLife")
            g.setrule(self.rg.slashed)

        # If this gets incremented, we panic and perform error-correction:
        pathological = 0

        # Draw the soups:
        for i in range(gsize * gsize):

            x = int(i % gsize)
            y = int(i / gsize)

            g.putcells(ashes[3*i], gspacing * x, gspacing * y)

        # Because why not?
        g.fit()
        g.update()

        # For error-correction:
        if (intergen > 0):
            g.setbase(2)
            g.setstep(intergen)
            g.step()

        # Apply rules to coalesce objects and expunge annoyances such as
        # blocks, blinkers, beehives and gliders:
        start_time = time.time()
        self.census(stepsize)
        end_time = time.time()
        self.ruletime += (end_time - start_time)

        # Now begin identifying objects:
        start_time = time.time()
        celllist = g.join(g.getcells(g.getrect()), [0])

        if (len(celllist) > 2):
            for i in range(0, len(celllist)-1, 3):
                if (g.getcell(celllist[i], celllist[i+1]) != 0):
                    self.gridobj(celllist[i], celllist[i+1], gsize, gspacing, pos)

        # If we have leftover unidentified objects, attempt to canonise them:
        while (len(self.unids) > 0):
            ux = int(0.5 + float(self.unids[-2])/float(gspacing))
            uy = int(0.5 + float(self.unids[-1])/float(gspacing))
            soupid = ux + (uy * gsize) + pos
            unidname = self.process_unid()
            if (unidname == "PATHOLOGICAL"):
                pathological += 1
            if (unidname != "nothing"):

                if ((unidname[0] == 'U') & (unidname[1] == 'S') & (unidname[2] == 'S')):
                    
                    # Union of standard spaceships:
                    countlist = unidname.split('_')
                    
                    self.incobject("xq4_6frc", int(float(countlist[1])))

                    for i in range(int(float(countlist[1]))):
                        self.awardpoints2(soupid, "xq4_6frc")

                    self.incobject("xq4_27dee6", int(float(countlist[2])))
                    for i in range(int(float(countlist[2]))):
                        self.awardpoints2(soupid, "xq4_27dee6")
                        
                    self.incobject("xq4_27deee6", int(float(countlist[3])))
                    for i in range(int(countlist[3])):
                        self.awardpoints2(soupid, "xq4_27deee6")
                        
                elif ((unidname[0] == 'x') & ((unidname[1] == 's') | (unidname[1] == 'p'))):
                    self.enter_unid(unidname, soupid, False)
                else:
                    if ((unidname[0] == 'x') & (unidname[1] == 'q') & (unidname[3] == '_')):
                        # Separates low-period (<= 9) non-standard spaceships in medium proximity:
                        self.enter_unid(unidname, soupid, True)
                    else:
                        self.incobject(unidname, 1)
                        self.awardpoints2(soupid, unidname)

        end_time = time.time()
        self.gridtime += (end_time - start_time)

        return pathological

    def stabilise_soups_parallel(self, root, pos, gsize, sym):

        souplist = [[sym, root + str(pos + i)] for i in range(gsize * gsize)]

        return self.stabilise_soups_parallel_orig(gsize, souplist, pos)

    def stabilise_soups_parallel_list(self, gsize, stringlist, pos):

        souplist = [s.split('/') for s in stringlist]

        return self.stabilise_soups_parallel_orig(gsize, souplist, pos)

    # This basically orchestrates everything:
    def stabilise_soups_parallel_orig(self, gsize, souplist, pos):

        ashes = []
        stepsize = 3

        g.new("Random soups")
        g.setalgo("QuickLife")
        g.setrule(self.rg.slashed)

        gspacing = 0

        # Generate and run the soups until stabilisation:
        for i in range(gsize * gsize):

            if (i < len(souplist)):

                sym = souplist[i][0]
                prehash = souplist[i][1]

                # Generate the soup from the SHA-256 of the concatenation of the
                # seed with the index:
                g.putcells(hashsoup(prehash, sym), 0, 0)

            # Run the soup until stabilisation:
            start_time = time.time()
            stepsize = max(stepsize, self.stabilise3())
            end_time = time.time()
            self.qlifetime += (end_time - start_time)

            # Ironically, the spelling of this variable is incurrrect:
            currrect = g.getrect()
            ashes.append(g.getcells(currrect))

            if (len(currrect) == 4):
                ashes.append(currrect[0])
                ashes.append(currrect[1])
                # Choose the grid spacing based on the size of the ash:
                gspacing = max(gspacing, 2*currrect[2])
                gspacing = max(gspacing, 2*currrect[3])
                g.select(currrect)
                g.clear(0)
            else:
                ashes.append(0)
                ashes.append(0)
            g.select([])

        # Account for any extra enlargement caused by running CoalesceObjects:
        gspacing += 2 ** (stepsize + 1) + 1000

        start_time = time.time()

        # Remember the dictionary, just in case we have a pathological object:
        prevdict = self.objectcounts.copy()
        prevscores = self.soupscores.copy()
        prevunids = self.superunids[:]

        # Process the soups:
        returncode = self.teenager(gsize, gspacing, ashes, stepsize, 0, pos)

        end_time = time.time()

        # Calculate the mean delay incurred (excluding qlifetime or error-correction):
        meandelay = (end_time - start_time) / (gsize * gsize)

        if (returncode > 0):
            if (self.skipErrorCorrection == False):
                # Arrrggghhhh, there's a pathological object! Usually this means
                # that naive stabilisation detection returned a false positive.
                self.resets += 1
                
                # Reset the object counts:
                self.objectcounts = prevdict
                self.soupscores = prevscores
                self.superunids = prevunids

                # 2^18 generations should suffice. This takes about 30 seconds in
                # HashLife, but error-correction only occurs very infrequently, so
                # this has a negligible impact on mean performance:
                gspacing += 2 ** 19
                stepsize = max(stepsize, 12)
                
                # Clear the universe:
                g.new("Error-correcting phase")
                self.teenager(gsize, gspacing, ashes, stepsize, 18, pos)

        # Erase any ashes. Not least because England usually loses...
        ashes = []

        # Return the mean delay so that we can use machine-learning to
        # find the optimal value of sqrtspp:
        return meandelay

    def reset(self):

        self.objectcounts = {}
        self.soupscores = {}
        self.alloccur = {}
        self.superunids = []
        self.unids = []

    # Pop the last unidentified object from the stack, and attempt to
    # ascertain its period and classify it.
    def process_unid(self):

        g.new("Unidentified object")
        g.setalgo("QuickLife")
        g.setrule(self.rg.slashed)
        y = self.unids.pop()
        x = self.unids.pop()
        livecells = self.unids.pop()
        bitstring = self.unids.pop()
        g.putcells(livecells, -x, -y, 1, 0, 0, 1, "or")
        period = self.bijoscar(1000)
        
        if (period == -1):
            # Infinite growth pattern, probably. Most infinite-growth
            # patterns are linear-growth (such as puffers, wickstretchers,
            # guns etc.) so we analyse to see whether we have a linear-
            # growth pattern:
            descriptor = linearlyse(1500)
            if (descriptor[0] == "y"):
                return descriptor

            # Similarly check for irregular power-law growth. This will
            # catch replicators, for instance. Spend around 375 000
            # generations; this seems like a reasonable amount of time.
            descriptor = powerlyse(8, 1500)
            if (descriptor[0] == "z"):
                return descriptor

            # It may be an unstabilised ember that slipped through the net,
            # but this will be handled by error-correction (unless it
            # persists another 2^18 gens, which is so unbelievably improbable
            # that you are more likely to be picked up by a passing ship in
            # the vacuum of space).
            self.superunids.append(livecells)
            self.superunids.append(x)
            self.superunids.append(y)
            
            return "PATHOLOGICAL"
        elif (period == 0):
            return "nothing"
        else:
            if (period == -4):

                triple = countxwsses()

                if (triple != (-1, -1, -1)):

                    # Union of Standard Spaceships:
                    return ("USS_" + str(triple[0]) + "_" + str(triple[1]) + "_" + str(triple[2]))

            
            canonised = canonise(abs(period))

            if (canonised == "#"):

                # Okay, we know that it's an oscillator or spaceship with
                # a non-astronomical period. But it's too large to canonise
                # in any of its phases (i.e. transcends a 40-by-40 box).
                self.superunids.append(livecells)
                self.superunids.append(x)
                self.superunids.append(y)
                
                # Append a suffix according to whether it is a still-life,
                # oscillator or moving object:
                if (period == 1):
                    descriptor = ("ov_s"+str(len(livecells)/2))
                elif (period > 0):
                    descriptor = ("ov_p"+str(period))
                else:
                    descriptor = ("ov_q"+str(0-period))

                return descriptor
            
            else:

                # Prepend a prefix according to whether it is a still-life,
                # oscillator or moving object:
                if (period == 1):
                    descriptor = ("xs"+str(int(len(livecells)/2))+"_"+canonised)
                elif (period > 0):
                    descriptor = ("xp"+str(int(period))+"_"+canonised)
                else:
                    descriptor = ("xq"+str(int(0-period))+"_"+canonised)

                if (bitstring > 0):
                    self.cache[bitstring] = descriptor

                return descriptor

    # This doesn't really do much, since unids should be empty and
    # actual pathological/oversized objects will rarely arise naturally.
    def display_unids(self):

        g.new("Unidentified objects")
        g.setalgo("QuickLife")
        g.setrule(self.rg.slashed)

        rowlength = 1 + int(math.sqrt(len(self.superunids)/3))

        for i in range(int(len(self.superunids)/3)):

            xpos = i % rowlength
            ypos = int(i / rowlength)

            g.putcells(self.superunids[3*i], xpos * (self.gridsize + 8) - self.superunids[3*i + 1], ypos * (self.gridsize + 8) - self.superunids[3*i + 2], 1, 0, 0, 1, "or")

        g.fit()
        g.update()

    def compactify_scores(self):

        # Number of soups to record:
        highscores = 100
        ilist = sorted(iter(self.soupscores.items()), key=operator.itemgetter(1), reverse=True)

        # Empty the high score table:
        self.soupscores = {}
        
        for soupnum, score in ilist[:highscores]:
            self.soupscores[soupnum] = score

    # Saves a machine-readable textual file containing the census:
    def save_progress(self, numsoups, root, symmetry='C1', save_file=True, payosha256_key=None):

        g.show("Saving progress...")

        # Count the total number of objects:
        totobjs = 0
        censustable = "@CENSUS TABLE\n"
        tlist = sorted(iter(self.objectcounts.items()), key=operator.itemgetter(1), reverse=True)
        for objname, count in tlist:
            if self.verifyobj(objname):
                totobjs += count
                censustable += objname + " " + str(count) + "\n"
            else:
                tlist.pop(objname)

        g.show("Writing header information...")

        # The MD5 hash of the root string:
        md5root = hashlib.md5(root.encode('utf-8')).hexdigest()

        # Header information:
        results = "@VERSION v1.2 Py3\n"
        results += "@MD5 "+md5root+"\n"
        results += "@ROOT "+root+"\n"
        results += "@RULE "+self.rg.alphanumeric+"\n"
        results += "@SYMMETRY "+symmetry+"\n"
        results += "@NUM_SOUPS "+str(numsoups)+"\n"
        results += "@NUM_OBJECTS "+str(totobjs)+"\n"

        results += "\n"

        # Census table:
        results += censustable

        g.show("Compactifying score table...")

        results += "\n"

        # Number of soups to record:
        highscores = 100

        results += "@TOP "+str(highscores)+"\n"

        ilist = sorted(iter(self.soupscores.items()), key=operator.itemgetter(1), reverse=True)

        # Empty the high score table:
        self.soupscores = {}
        
        for soupnum, score in ilist[:highscores]:
            self.soupscores[soupnum] = score
            results += str(soupnum) + " " + str(score) + "\n"

        g.show("Saving soupids for rare objects...")

        results += "\n@SAMPLE_SOUPIDS\n"
        for objname, count in tlist:
            # blinkers and gliders have no alloccur[] entry for some reason,
            # so the line below avoids errors in B3/S23, maybe other rules too?
            if objname in self.alloccur:
                results += objname
                for soup in self.alloccur[objname]:
                    results += " " + str(soup)
                results += "\n"

        g.show("Writing progress file...")

        dirname = g.getdir("data")
        separator = dirname[-1]
        progresspath = dirname + "apgsearch" + separator + "progress" + separator
        if not os.path.exists(progresspath):
            os.makedirs(progresspath)

        filename = progresspath + "search_" + md5root + ".txt"
        g.warn(filename)
        try:
            f = open(filename, 'w')
            f.write(results)
            f.close()
        except:
            g.warn("Unable to create progress file:\n" + filename)

        if payosha256_key is not None:
            if (len(payosha256_key) > 0):
                return catagolue_results(results, payosha256_key, "post_apgsearch_haul")

    # Save soup RLE:
    def save_soup(self, root, soupnum, symmetry):

        # Soup pattern will be stored in a temporary directory:
        souphash = hashlib.sha256((root + str(soupnum)).encode('utf-8'))
        rlepath = souphash.hexdigest()
        rlepath = g.getdir("temp") + rlepath + ".rle"
        
        results = "<a href=\"open:" + rlepath + "\">"
        results += str(soupnum)
        results += "</a>"

        # Try to write soup patterns to file "rlepath":
        try:
            g.store(hashsoup(root + str(soupnum), symmetry), rlepath)
        except:
            g.warn("Unable to create soup pattern:\n" + rlepath)

        return results
        
    # Display results in Help window:
    def display_census(self, numsoups, root, symmetry):

        dirname = g.getdir("data")
        separator = dirname[-1]
        apgpath = dirname + "apgsearch" + separator
        objectspath = apgpath + "objects" + separator + self.rg.alphanumeric + separator
        if not os.path.exists(objectspath):
            os.makedirs(objectspath)

        results = "<html>\n<title>Census results</title>\n<body bgcolor=\"#FFFFCE\">\n"
        results += "<p>Census results after processing " + str(numsoups) + " soups (seed = " + root + ", symmetry = " + symmetry + "):\n"

        tlist = sorted(iter(self.objectcounts.items()), key=operator.itemgetter(1), reverse=True)    
        results += "<p><center>\n"
        results += "<table cellspacing=1 border=2 cols=2>\n"
        results += "<tr><td> Object </td><td align=center> Common name </td>\n"
        results += "<td align=right> Count </td><td> Sample occurrences </td></tr>\n"
        for objname, count in tlist:
            if self.verifyobj(objname):
                if (objname[0] == 'x'):
                    if (objname[1] == 'p'):
                        results += "<tr bgcolor=\"#CECECF\">"
                    elif (objname[1] == 'q'):
                        results += "<tr bgcolor=\"#CEFFCE\">"
                    else:
                        results += "<tr>"
                else:
                    results += "<tr bgcolor=\"#FFCECE\">"
                results += "<td>"
                results += " "
                
                # Using "open:" link enables one to click on the object name to open the pattern in Golly:
                rlepath = objectspath + objname + ".rle"
                if (objname[0] == 'x'):
                    results += "<a href=\"open:" + rlepath + "\">"
                # If the name is longer than that of the block-laying switch engine:
                if len(objname) > 51:
                    # Contract name and include ellipsis:
                    results += objname[:40] + "…" + objname[-10:]
                else:
                    results += objname
                if (objname[0] == 'x'):
                    results += "</a>"
                results += " "

                if (objname[0] == 'x'):
                    # save object in rlepath if it doesn't exist (and also in apgcodetorle
                    if not os.path.exists(rlepath):
                        # Canonised objects are at most 40-by-40:
                        rledata = "x = 40, y = 40, rule = " + self.rg.slashed + "\n"
                        # https://ferkeltongs.livejournal.com/15837.html
                        compact = objname.split('_')[1] + "z"
                        i = 0
                        strip = []
                        while (i < len(compact)):
                            c = ord2(compact[i])
                            if (c >= 0):
                                if (c < 32):
                                    # Conventional character:
                                    strip.append(c)
                                else:
                                    if (c == 35):
                                        # End of line:
                                        if (len(strip) == 0):
                                            strip.append(0)
                                        for j in range(5):
                                            for d in strip:
                                                if ((d & (1 << j)) > 0):
                                                    rledata += "o"
                                                else:
                                                    rledata += "b"
                                            rledata += "$\n"
                                        strip = []
                                    else:
                                        # Multispace character:
                                        strip.append(0)
                                        strip.append(0)
                                        if (c >= 33):
                                            strip.append(0)
                                        if (c == 34):
                                            strip.append(0)
                                            i += 1
                                            d = ord2(compact[i])
                                            for j in range(d):
                                                strip.append(0)
                            i += 1
                        # End of pattern representation:
                        rledata += "!\n"
                        try:
                            f = open(rlepath, 'w')
                            f.write(rledata)
                            f.close()
                        except:
                            g.warn("Unable to create object pattern:\n" + rlepath)
                

                results += "</td><td align=center> "
                if (objname in self.commonnames):
                    results += self.commonnames[objname][0]
                results += " </td><td align=right> " + str(count) + " "
                results += "</td><td>"
                if objname in self.alloccur:
                    results += " "
                    for soup in self.alloccur[objname]:
                        results += self.save_soup(root, soup, symmetry) 
                        results += " "
                results += "</td></tr>\n"
            else:
                tlist.pop(objname)
        results += "</table>\n</center>\n"

        ilist = sorted(iter(self.soupscores.items()), key=operator.itemgetter(1), reverse=True)
        results += "<p><center>\n"
        results += "<table cellspacing=1 border=2 cols=2>\n"
        results += "<tr><td> Soup number </td><td align=right> Score </td></tr>\n"
        for soupnum, score in ilist[:50]:
            results += "<tr><td> "
            results += self.save_soup(root, soupnum, symmetry)
            results += " </td><td align=right> " + str(score) + " </td></tr>\n"
        
        results += "</table>\n</center>\n"
        results += "</body>\n</html>\n"
        
        htmlname = apgpath + "latest_census.html"
        try:
            f = open(htmlname, 'w')
            f.write(results)
            f.close()
            g.open(htmlname)
        except:
            g.warn("Unable to create html file:\n" + htmlname)
            

# Converts a base-36 case-insensitive alphanumeric character into a
# numerical value.
def ord2(char):

    x = ord(char)

    if ((x >= 48) & (x < 58)):
        return x - 48

    if ((x >= 65) & (x < 91)):
        return x - 55

    if ((x >= 97) & (x < 123)):
        return x - 87

    return -1


def apg_verify(rulestring, symmetry, payoshakey):

    verifysoup = Soup()
    verifysoup.rg.setrule(rulestring)
    verifysoup.rg.saveAllRules()

    return_point = [None]

    catagolue_results(rulestring+"\n"+symmetry+"\n", payoshakey, "verify_apgsearch_haul", endpoint="/verify", return_point=return_point)

    if return_point[0] is not None:

        resplist = return_point[0].decode('utf-8').split("\n")

        if ((len(resplist) >= 4) and (resplist[1] == "yes")):

            md5 = resplist[2]
            passcode = resplist[3]

            stringlist = resplist[4:]

            stringlist = [s for s in stringlist if (len(s) > 0 and s[0] != '*')]

            # g.exit(stringlist[0])

            gsize = 3

            pos = 0

            while (len(stringlist) > 0):

                while (gsize * gsize > len(stringlist)):

                    gsize -= 1

                listhead = stringlist[:(gsize*gsize)]
                stringlist = stringlist[(gsize*gsize):]

                verifysoup.stabilise_soups_parallel_list(gsize, listhead, pos)

                pos += (gsize * gsize)

            # verifysoup.display_census(-1, "verify", "verify")

            payload = "@MD5 "+md5+"\n"
            payload += "@PASSCODE "+passcode+"\n"
            payload += "@RULE "+rulestring+"\n"
            payload += "@SYMMETRY "+symmetry+"\n"

            tlist = sorted(iter(verifysoup.objectcounts.items()), key=operator.itemgetter(1), reverse=True)

            for objname, count in tlist:

                payload += objname + " " + str(count) + "\n"

            catagolue_results(payload, payoshakey, "submit_verification", endpoint="/verify")

symmstring = 'C1'
inflationamount = 0
def apg_main():
    global symmstring
    global inflationamount
    # ---------------- Hardcode the following inputs if running without a user interface ----------------
    orignumber = int(g.getstring("How many soups to search between successive uploads?", "1000000"))
    rulestring = g.getstring("Which rule to use?", "B3/S23")
    g.setrule(rulestring)
    rulestring = g.getrule()
    symmstring = g.getstring("What symmetries to use?", "C1")
    payoshakey = g.getstring("Please enter your key (visit "+get_server_address()+"/payosha256 in your browser).", "#anon")
    # ---------------------------------------------------------------------------------------------------

    # Sanitise input:
    orignumber = max(orignumber, 100000)
    orignumber = min(orignumber, 100000000)
    number = orignumber
    initpos = 0
    newsymmstring = symmstring
    inflationamount = 0
    while newsymmstring[0] == 'i':
        newsymmstring = newsymmstring[1:]
        inflationamount = inflationamount+1
    if newsymmstring not in ["1x256X2+1", "1x256X2", "32x32", "25p", "75p", "1x256", "2x128", "4x64", "8x32", "C1", "C2_1", "C2_2", "C2_4", "C4_1", "C4_4", "D2_+1", "D2_+2", "D2_x", "D4_+1", "D4_+2", "D4_+4", "D4_x1", "D4_x4", "D8_1", "D8_4", 'Pseudo_C1_Test', 'Pseudo_C2_1_Test', 'Pseudo_C2_2_Test', 'Pseudo_C2_4_Test', 'Pseudo_C4_1_Test', 'Pseudo_C4_4_Test', 'Pseudo_D2_+1_Test', 'Pseudo_D2_+2_Test', 'Pseudo_D2_x_Test', 'Pseudo_D4_+1_Test', 'Pseudo_D4_+2_Test', 'Pseudo_D4_+4_Test', 'Pseudo_D4_x1_Test', 'Pseudo_D4_x4_Test', 'Pseudo_D8_1_Test', 'Pseudo_D8_4_Test', 'Pseudo_1x256X2+1_Test', 'Pseudo_1x256X2_Test', 'Pseudo_32x32_Test', 'Pseudo_25p_Test', 'Pseudo_75p_Test', 'Pseudo_8x32_Test', 'Pseudo_4x64_Test', 'Pseudo_2x128_Test', 'Pseudo_1x256_Test']:
        g.exit(symmstring+" is not a valid symmetry option")
    quitapg = False
    # Create associated rule tables:
    soup = Soup()
    soup.pseudo = False
    if symmstring.lower().count('pseudo') > 0:
        #Enable pseudo object recognition if searching a pseudo symmetry.
        soup.pseudo = True
    soup.rg.setrule(rulestring)
    soup.rg.saveAllRules()

    # We have 100 soups per page, instead of one. This parallel approach
    # was suggested by Tomas Rokicki, and results in approximately a
    # fourfold increase in soup-searching speed!
    sqrtspp_optimal = 10

    # Initialise the census:
    start_time = time.time()
    f = (lambda x: 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'[x % 56])
    rootstring = ''.join(map(f, list(hashlib.sha256((payoshakey.encode('utf-8') + str(datetime.datetime.now()).encode('utf-8'))).digest()[:12]))) 
    scount = 0

    while (quitapg == False):

        # Peer-review some soups:
        # The 'for' loop has been replaced with a 'while' loop to allow sqrtspp
        # to vary during runtime. The idea is that apgsearch can apply a basic
        # form of machine-learning to dynamically locate the optimum sqrtspp:
        while (scount < number):

            delays = [0.0, 0.0, 0.0]

            for i in range(1000):

                page_time = time.time()

                sqrtspp = (sqrtspp_optimal + (i % 3) - 1) if (i < 150) else (sqrtspp_optimal)

                # Don't overrun:
                while (scount + sqrtspp * sqrtspp > number):
                    sqrtspp -= 1

                meandelay = soup.stabilise_soups_parallel(rootstring, scount + initpos, sqrtspp, symmstring)
                if (i < 150):
                    delays[i % 3] += meandelay
                scount += (sqrtspp * sqrtspp)

                current_speed = int((sqrtspp * sqrtspp)/(time.time() - page_time))
                alltime_speed = int((scount)/(time.time() - start_time))
                
                g.show(str(scount) + " soups processed (" + str(current_speed) +
                       " per second current; " + str(alltime_speed) + " overall)" +
                       " : (type 's' to see latest census or 'q' to quit).")
                
                event = g.getevent()
                if event.startswith("key"):
                    evt, ch, mods = event.split()
                    if ch == "s":
                        soup.save_progress(scount, rootstring, symmstring)
                        soup.display_census(scount, rootstring, symmstring)
                    elif ch == "q":
                        quitapg = True
                        break

                if (scount >= number):
                    break
                
            if (quitapg == True):
                break

            # Change sqrtspp to a more optimal value:
            if (scount < number):
                sqrtspp_new = sqrtspp_optimal

                if (delays[0] < delays[1]):
                    sqrtspp_new = sqrtspp_optimal - 1
                if ((delays[2] < delays[1]) and (delays[2] < delays[0])):
                    sqrtspp_new = sqrtspp_optimal + 1

                sqrtspp_optimal = sqrtspp_new
                sqrtspp_optimal = max(sqrtspp_optimal, 5)

            # Compactify highscore table:
            soup.compactify_scores()

        if (quitapg == False):
            # Save progress, upload it to Catagolue, and reset the census if successful:
            a = soup.save_progress(scount, rootstring, symmstring, payosha256_key=payoshakey)
            if (a == 0):
                # Reset the census:
                soup.reset()
                start_time = time.time()
                f = (lambda x: 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'[x % 56])
                rootstring = ''.join(map(f, list(hashlib.sha256((payoshakey.encode('utf-8') + str(datetime.datetime.now()).encode('utf-8'))).digest()[:12])))
                scount = 0
                number = orignumber
            else:
                number += orignumber

    end_time = time.time()

    soup.save_progress(scount, rootstring, symmstring, payosha256_key=payoshakey)

    soup.display_unids()
    soup.display_census(scount, rootstring, symmstring)

def symmetry_test():

    g.new("Symmetry test")

    symmetries = [["1x256X2+1", "1x256X2", "32x32", "25p", "75p", "C1", "8x32", "4x64", "2x128", "1x256"],
                  ["C2_1", "C2_2", "C2_4"],
                  ["C4_1", "C4_4"],
                  ["D2_+1", "D2_+2", "D2_x"],
                  ["D4_+1", "D4_+2", "D4_+4", "D4_x1", "D4_x4"],
                  ["D8_1", "D8_4", 'Pseudo_C1_Test', 'Pseudo_C2_1_Test', 'Pseudo_C2_2_Test', 'Pseudo_C2_4_Test', 'Pseudo_C4_1_Test', 'Pseudo_C4_4_Test', 'Pseudo_D2_+1_Test', 'Pseudo_D2_+2_Test', 'Pseudo_D2_x_Test', 'Pseudo_D4_+1_Test', 'Pseudo_D4_+2_Test', 'Pseudo_D4_+4_Test', 'Pseudo_D4_x1_Test', 'Pseudo_D4_x4_Test', 'Pseudo_D8_1_Test', 'Pseudo_D8_4_Test', 'Pseudo_1x256X2+1_Test', 'Pseudo_1x256X2_Test', 'Pseudo_32x32_Test', 'Pseudo_25p_Test', 'Pseudo_75p_Test', 'Pseudo_8x32_Test', 'Pseudo_4x64_Test', 'Pseudo_2x128_Test', 'Pseudo_1x256_Test']]
    for i in range(len(symmetries)):
        for j in range(len(symmetries[i])):

            g.putcells(hashsoup("sym_test", symmetries[i][j]), 120 * j + 60 * (i % 2), 80 * i)
    g.fit()

# Run the soup-searching script:
apg_main()
#I have removed verification to prevent the client from wrongly rejecting good hauls.
g.show('Done')
