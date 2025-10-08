# c4 => a better c
c4 is a c-like system language with modern features and better memory management philosophy.

c4 is aimed to be easy to understand and with little or no hidden magic,but powerful enough.

simple and safer and as fast as c


## Memory Management

we aim to provide mechanisms instead of policies,which means our memory management philosophy is what we like to call "assisted manual memory management"

how this works is as follows,we have two keywords [defer] and [scoped defer]

defer works as Golang's defer works

```Go
    
    defer print("hello world")

```

the `print("hello world")` is executed just before the fucntion returns


the [scoped defer] works similarly but instead of being executed at the end of the function,the deferred function is executed at the end of the current scope



### How this relates to memory management

memory management simply relies on the programmer knowing which scope the memory should be deallocated and it's a good programming practice to defer the free before doing anything else.

That way memory is always freed without the programmer hving to worry about different execution control paths and other nasty surprises


```C

    char *str = malloc(100)
    defer free(str) // free called at the end of the function

    if x = 100:
        char *str1 = malloc(200)
        scoped defer free(str1)  // free called at the end of the current scope
    :

```

Our main priorities are security,efficiency and simplicity










