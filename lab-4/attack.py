# Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of
# which can be found via http://creativecommons.org (and should be included as
# LICENSE.txt within the associated archive or repository).

import sys, subprocess

def interact( G ) :
  # send      G      to   attack target

  target_in.write( '%s\n' % ( G ) ) ; target_in.flush()

  # receive ( t, r ) from attack target

  t = int( target_out.readline().strip() )
  r = int( target_out.readline().strip() )

  return ( t, r )

def attack() :
  # select a hard-coded guess ...
  length = 0
  g = list("")
  for i in range(1,100):
      g = g + ['1']
      G = "".join(g)
      (t, r) = interact(G)
      if (t >=1):
          length = i
          break

  for j in range(0, length):
      for k in range(64,123):
          g[j] = str(chr(k))
          G = "".join(g)
          (t,r) = interact(G)
          if(t >= 1 + (j+1)):
              break


  # ... then interact with the attack target
  G = "".join(g)
  ( t, r ) = interact( G )

  # print all of the inputs and outputs

  print 'G = %s' % ( G )
  print 't = %d' % ( t )
  print 'r = %d' % ( r )

if ( __name__ == '__main__' ) :
  # produce a sub-process representing the attack target

  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

  # construct handles to attack target standard input and output

  target_out = target.stdout
  target_in  = target.stdin

  # execute a function representing the attacker

  attack()
