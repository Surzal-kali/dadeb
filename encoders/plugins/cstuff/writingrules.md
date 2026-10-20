# Rules for writing shellcode in C

## General Guidelines

- Keep your shellcode small and efficient.
- Remember the compiling environment and architecture dictate the shellcode's behavior.
- Avoid using null bytes in your shellcode, as they can terminate strings prematurely.
- If you keep to C, ensure that your shellcode is position-independent and does not rely on absolute addresses. Don't import global libraries like they exist, because, for example, if you import stdio.h, it will not be available in the target environment.
