# ModifyingFreeBSD
Changes to the FreeBSD operating system kernel to implement different scheduling algorithms, paging algorithms, and file encryption/decryption.

Read DESIGN.pdf and WRITEUP.pdf for more info on each project and the results.

Scheduling: 
Modified FreeBSD's existing scheduler for threads and processes, which uses FIFO (first in first out) and assigns each    thread a run queue based on priority. We implemented "Splatter Scheduling" which, instead of using a priority, assigns each thread a random run queue. We also implemented a priority queue instead of their original FIFO queue. 
We compared the 4 cases and measured performance:
  1. Case 1: FIFO, No Splatter 
  2. Case 2: Priority Queue, No Splatter
  3. Case 3: FIFO, Splatter
  4. Case 4: Priority Queue, Splatter
  
Paging:
Modified FreeBSD's existing page replacement algorithm for virtual memory with a "Bon Chance" page replacement algorithm. This algorithm assigns each activity a random activity count between 1-32 when it is placed in the active queue, insert pages with an even page number at the front of the free list and odd pages at the back. Also increases the decay rate of pages - instead of subtracting 1 from the activity count each tick, divide by 2 and then subtract 1.

CryptoFS:
Implemented a cryptographic file system with FUSE. User can set a key for themselves and then protect a file with the key. If the user attempts to read the file, it will automatically decrypt the file and encrypt it again when the user writes to it or closes it. If a different user attempts to read it, they will see gibberish. 
