# CakeFS
CakeFS: Hiding Under Layers of Fluff 

Proposed Solution:
Create a fake file system with 3 layers; For the baseline, a fake file system will be created to hide the real one, with both the normal and custom file system working. The real file system is defined as the one that holds the suspicious content, and the fake one the one that is used to hide the real one. For the second level, the team will hide the real “illegal” data into the metadata of the fake file system. Finally, for the third level, the team will hide it such that a normal forensics analyst is unable to tell that there’s important data located there. 
