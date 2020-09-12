#pragma once

//Suported Datatypes
#define TYPE_ULONG 0x1
#define TYPE_BOOLEAN 0x2
#define TYPE_UNICODE_STRING 0x3


//Vector struct for storing vector related information
typedef struct Vector
{
	PVOID pVecMem; //Pointer to the allocated memory for the vector
	ULONG sizeVector; //Total size of the vector in memory
	size_t sizeElement; //The size of the last element located in the vector (used for pop_back)
	size_t sizeLastElement; //Only for UNICODE_STRING
	USHORT elementCount;
	USHORT vectorType; //Store vector's datatype
} VEC, *PVEC;

ULONG vecID; //Store Vector ID's

//Vector Functions
ULONG vector_create(USHORT type); //Used to create a new struct and allocate the memory for the vector
void vector_delete(ULONG id); //Used to 
void vector_clear(ULONG id);
void vector_push(ULONG id, void* element); //Used to create a new element on top of the last element in the vector
void vector_pop(ULONG id); //Used to delete the last element in the vector
void* vector_get(ULONG id, USHORT index);
void vector_sort(ULONG id);