# c4 => a better c
c4 is a c-like system language with modern features and better memory management philosophy.

c4 is aimed to be easy to understand and with little or no hidden magic,but powerful enough.

simple and safer and as fast as c


## Memory Management

we aim to provide mechanisms instead of policies,which means our memory management philosophy is what we like to call "assisted manual memory management"

how this works is as follows,we have two keywords [defer] and [scoped defer]

defer works as Golang's defer works

"""Go
    
    defer print("hello world")

"""
