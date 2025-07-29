# apgsearch-Py3
## A hacked version of apgsearch which works in Python 3 and has additional features and symmetries.
### Introduction
apgsearch refers to a range of programs written by Adam P. Goucher, which creates random arrangements of cells (referred to as soups)
in cellular automata (usually ones related to Conway's Game of Life), and then runs them until they stabilise.
v1, released in February 2015, was the last version written in Python, with v2-5 written in C++.
However, some people cannot use the C++ versions, as they require x86 or arm64 architecture, and even if their computer supports it, they can have problems with compiling them, and in order to practice Python programming, I decided to try and push the Python version to its limits.
### How to run
You will need:
- A recent version of Golly, a CA viewing and editing program. See https://golly.sourceforge.io. At the time of writing, v4.3 is the latest version, but v5.0 is in the works, according to a recent forum post.
- A fairly recent version of Python 3 - v3.9+ is recommended. You will need to tell Golly the location of your Python installation (python3*.dll on Windows or libpython3*.so on Linux). If it does not accept it at first, open your gollyprefs file in a text editor and add the file path manually.
- The Python script.
Save the Python script in Golly's script folder, then open Golly and go to File > Run Script and run it.
You will be asked to enter:
- A number of soups - I would choose a number that makes a haul take between 15 minutes and an hour.
- A rule - you can enter any isotropic range-1 Moore rule. Conway's Game of Life is B3/S23, for example.
- A symmetry - C1 means no symmetry at all. See the subsection below for an explanation of symmetries.
- A payosha256 key - if you want to contribute anonymously, then use #anon. Otherwise, go to https://catagolue.hatsya.com, create an account, and then create a key under your preferred pseudonym. Then enter the key whenever you do a search.
#### Symmetries
Entering a symmetry will make the program search for soups with that specific symmetry.
The avaliable symmetries are:
- C1 - A 16x16 soup with no symmetry at all. Invariant under 360 degree rotation.
- C2_1 - Invariant under 180 degree rotation around the centre of a cell.
- C2_2 - Invariant under 180 degree rotation around the middle of two cells..
- C2_4 - Invariant under 180 degree rotation around a point where the vertices of four cells meet.
- C4_1 - Invariant under 90 degree rotation around the centre of a cell.
- C4_4 - Invariant under 90 degree rotation around the intersection of two grid lines.
- D2_+1 - Invariant under reflection in a line bisecting a row of cells.
- D2_+2 - Invariant under reflection in a line between two rows of cells.
- D2_x - Invariant under reflection in a diagonal line.
- D4_+1 - Invariant under reflection in two perpendicular lines, which intersect at the centre of a cell, as well as under 180 degree rotation.
- D4_+2 - Invariant under reflection in two perpendicular lines, which intersect at the middle of two cells, as well as under 180 degree rotation.
- D4_+4 - Invariant under reflection in two perpendicular lines, which intersect where the vertices of four cells meet, as well as under 180 degree rotation.
- D4_x1 - Invariant under reflection in two perpendicular diagonal lines, which intersect at the centre of a cell, as well as under 180 degree rotation.
- D4_x4 - Invariant under reflection in two perpendicular diagonal lines, which intersect where the vertices of four cells meet, as well as under 180 degree rotation.
- D8_1 - Invariant under reflection in four lines which intersect at the centre of a cell, as well as under 90 degree rotation.
- D8_4 - Invariant under reflection in four lines which intersect where the vertices of four cells meet, as well as under 90 degree rotation.
- 8x32, 4x64, 2x128, 1x256 - Different sizes for the initial soups. These are considered seperate symmetries.
- 1x256X2 and 1x256X2+1 - Made up of two copies of a 1x256 soup.
##### Pseudo-object symmetries
Fairly commonly, you will get two or more objects occurring right next to each other (with only a single empty row/column between them) but not influencing each other. The constituent objects get separated by the program by default. If you instead wish to count them as a single object (and upload to a separate census), then enter the symmetry as 'Pseudo_<symmetry>_Test' (ignoring the quotes and replacing <symmetry> with your desired symmetry). 
##### Inflated symmetries
By adding the prefix 'i' to a symmetry, each 1x1 cell in a soup gets replaced by a 2x2 block of cells. This may have occasional uses, but it tends to slow the searching speed down significantly, so I would not recommend using it.
You can stack the prefix - e.g 'iii1x256' will replace each cell with a 8x8 block of cells, and if combining it with pseudo-object symmetries, 'i' goes first - e.g 'iPseudo_C1_Test'.

### Old Features
 -  Processes roughly 100 soups per (second . core . GHz), using caching
    and machine-learning to optimise itself during runtime.

 -  Can perfectly identify oscillators with period < 1000, well-separated
    spaceships of low period, and certain infinite-growth patterns (such
    guns and puffers, including both naturally-occurring types of switch
    engine).

 -  Separates most pseudo-objects into their constituent parts, including
    all pseudo-still-lifes of 18 or fewer live cells (which is the maximum
    theoretically possible, given there is a 19-cell pseudo-still-life
    with two distinct decompositions). 

 -  Correctly separates non-interacting standard spaceships, irrespective
    of their proximity. In particular, a LWSS-on-LWSS is registered as two
    LWSSes, whereas an LWSS-on-HWSS is registered as a single spaceship
    (since they interact by suppressing sparks).

 -  At least 99.9999999999% reliable at identifying objects in asymmetrical
    soups in B3/S23 (based on the fact that out of over 10^12 objects that
    have appeared, there are no errors).

 -  Scores soups based on the total excitement of the ash objects.

 -  Support for other outer-totalistic rules, including detection and
    classification of various types of infinite growth.

 - Support for symmetrical soups.

 - Uploads results to the server at https://catagolue.hatsya.com (which
    currently has collected over 2.7 * 10^12 objects).
### New features
- Source code adapted to Python 3 (original was written in Python 2).
- New symmetries - different grid sizes taken from wwei47's hacked version, inflated symmetries added by me (PK22).
- Pseudo-object symmetries - pseudo still lifes and oscillators can be counted as 'true' objects when uploading to separate censuses.
- Program-side object verification - erroneous objects were uploaded to Pseudo_C1_Test in one case, so the newest version runs certain objects through one period and throws them out if they fail verification.
- Haul verification removed in order to prevent wrongful rejection of valid hauls.
### Uploading of results
You can see the results on Catagolue - if searching <rule> and <symmetry>, then you can find them at https://catagolue.hatsya.com/census/<rule>/<symmetry> - make sure that <rule> is in the form b***s***, replacing the asterisks with the birth and survival conditions of your rule.
Once uploaded, it may take up to 12 minutes for your haul to be committed. If uploading to a standard symmetry in a well-investigated rule, it will have to be peer-reviewed, which is done automatically by people running more modern versions of apgsearch.
### More info
More information can be found on LifeWiki.
- Information about apgsearch - https://conwaylife.com/wiki/Apgsearch
- Information about contributing to Catagolue - https://conwaylife.com/wiki/Tutorials/Contributing_to_Catagolue
- My user page with a copy of the code and bug reports - https://conwaylife.com/wiki/User:PK22/apgsearch_Py3
