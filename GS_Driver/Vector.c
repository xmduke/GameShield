#include <ntdef.h>
#include <wdm.h>
#include "Vector.h"

PVEC pVec[1024]; //Store vec ptr's
#define DebugMessage(x, ...) DbgPrintEx(0, 0, x, __VA_ARGS__)

//Vector Functions
ULONG vector_create(USHORT type)
{
	vecID++;
	pVec[vecID] = ExAllocatePool(NonPagedPool, sizeof(VEC));
	if (!pVec[vecID])
	{
		DebugMessage("[VECTOR] Failed to allocate Memory for vector object\n");
		vecID = (ULONG)0;
		return vecID;
	}

	//Allocate standard size (1024 Bytes) for vector elements
	pVec[vecID]->pVecMem = ExAllocatePool(NonPagedPool, 1024);
	if (!pVec[vecID]->pVecMem)
	{
		DebugMessage("[VECTOR] Failed to allocate Memory for vector elements\n");
		ExFreePool((PVOID)pVec[vecID]);
		vecID = (ULONG)0;
		return vecID;
	}

	//Get Datatype for Vector
	switch (type)
	{
		case TYPE_ULONG:
		{
			pVec[vecID]->vectorType = TYPE_ULONG;
			pVec[vecID]->sizeElement = sizeof(ULONG);
			break;
		}

		case TYPE_BOOLEAN:
		{
			pVec[vecID]->vectorType = TYPE_BOOLEAN;
			pVec[vecID]->sizeElement = sizeof(BOOLEAN);
			break;
		}

		case TYPE_UNICODE_STRING: //size not defined
		{
			pVec[vecID]->vectorType = TYPE_UNICODE_STRING;
			pVec[vecID]->sizeElement = (size_t)0;
			break;
		}
		default:
		{
			DebugMessage("[VECTOR] Datatype is not defined\n", vecID);
			ExFreePool((PVOID)pVec[vecID]);
			vecID = (ULONG)0;
			return vecID;
		}
	}

	//Everything worked, increment vecID and init vec struct
	pVec[vecID]->sizeVector = (ULONG)0;
	pVec[vecID]->elementCount = (ULONG)1;
	DebugMessage("[VECTOR] Vector created. (ID: %d)\n", vecID);
	return vecID;
}


void vector_delete(ULONG id)
{
	//Check ID first
	if (!pVec[id])
	{
		DebugMessage("[VECTOR] Vector (ID: %d) does not exist\n", id);
		return;
	}

	ExFreePool(pVec[id]->pVecMem);
	ExFreePool((PVOID)pVec[id]);
}

void vector_clear(ULONG id)
{
	//Check ID first
	if (!pVec[id])
	{
		DebugMessage("[VECTOR] Vector (ID: %d) does not exist\n", id);
		return;
	}

	if (RtlZeroMemory(pVec[id]->pVecMem, pVec[id]->sizeVector))
		DebugMessage("[VECTOR] Vector (ID: %d) cleared successfully\n", id);
	else
		DebugMessage("[VECTOR] Failed to clear Vector (ID: %d)\n", id);
}


void vector_push(ULONG id, void* element)
{
	//Check ID first
	if (!pVec[id])
	{
		DebugMessage("[VECTOR] Vector (ID: %d) does not exist\n", id);
		return;
	}

	if (pVec[id]->vectorType != TYPE_UNICODE_STRING)
	{
		switch (pVec[id]->vectorType)
		{
			case TYPE_ULONG: //Push ULONG element
			{
				PULONG newElement = (PULONG)element; //Get the new element as ULONG
				ULONG startPos = pVec[id]->sizeVector; //Pos after last element (first is 0)
				PULONG pTemp = (PULONG)pVec[id]->pVecMem + startPos; //Pos in buffer

				if (RtlCopyMemory((PULONG)pTemp, newElement, pVec[id]->sizeElement))
				{
					pVec[id]->elementCount++;
					pVec[id]->sizeVector += pVec[id]->sizeElement;
					DebugMessage("[VECTOR] Vector (ID: %d) new element", id);
				}
			}break;

			case TYPE_BOOLEAN: //Push BOOLEAN element
			{
				PBOOLEAN newElement = (PBOOLEAN)element; //Get the new element as BOOLEAN
				ULONG startPos = pVec[id]->elementCount * pVec[id]->sizeElement; //Pos after last element (first is 0)
				PBOOLEAN pTemp = (PBOOLEAN)pVec[id]->pVecMem + startPos; //Pos in buffer

				if (RtlCopyMemory((PBOOLEAN)pTemp, newElement, pVec[id]->sizeElement))
				{
					pVec[id]->elementCount++;
					pVec[id]->sizeVector += pVec[id]->sizeElement;
					DebugMessage("[VECTOR] Vector (ID: %d) new element", id);
				}
			}break;
		}
	}
	else
	{
		//Push new UNICODE_STRING element (undefined size, must find out size first)
		if (!pVec[id]->elementCount) //No elements yet
		{
			PUNICODE_STRING newElement = (PUNICODE_STRING)element;
			size_t size = (size_t)newElement->MaximumLength;

			if (RtlCopyMemory((PUNICODE_STRING)pVec[id]->pVecMem, newElement, size))
			{
				pVec[id]->elementCount++;
				pVec[id]->sizeVector += size; //Update Postion
				pVec[id]->sizeLastElement = size; //Store size of pushed UNICODE_STRING
				DebugMessage("[VECTOR] Vector (ID: %d) new element", id);
			}
		}
	}
}

void vector_pop(ULONG id)
{
	//Check ID first
	if (!pVec[id])
	{
		DebugMessage("[VECTOR] Vector (ID: %d) does not exist\n", id);
		return;
	}

	//No more elements
	if (!pVec[id]->elementCount)
	{
		DebugMessage("[VECTOR] Vector (ID: %d) is empty\n", id);
		return;
	}

	if (pVec[id]->vectorType != TYPE_UNICODE_STRING)
	{
		ULONG startPos = pVec[id]->sizeVector - pVec[id]->sizeElement;
		void* pTemp = (char*)pVec[id]->pVecMem + startPos;

		if (RtlZeroMemory(pTemp, pVec[id]->sizeElement))
		{
			pVec[id]->elementCount--;
			pVec[id]->sizeVector -= pVec[id]->sizeElement;
			DebugMessage("[VECTOR] Vector (ID: %d) cleared last element\n", id);
		}
	}
	else //Pop last UNICODE_STRING
	{
		ULONG startPos = pVec[id]->sizeVector - pVec[id]->sizeLastElement;
		PUNICODE_STRING pTemp = (PUNICODE_STRING)pVec[id]->pVecMem + startPos;

		if (RtlZeroMemory(pTemp, pVec[id]->sizeLastElement))
		{
			pVec[id]->elementCount--;
			pVec[id]->sizeVector -= pVec[id]->sizeLastElement;
			DebugMessage("[VECTOR] Vector (ID: %d) cleared last element\n", id);
		}
	}
}

//Return pointer where the elemented is stored
void* vector_get(ULONG id, USHORT index)
{
	if (pVec[id]->vectorType != TYPE_UNICODE_STRING)
	{		
		if (index > pVec[id]->elementCount)
			return NULL; //Index not in range

		ULONG elementPos = (ULONG)(pVec[id]->sizeElement * index);
		switch (pVec[id]->vectorType)
		{
			case TYPE_ULONG:
			{
				PULONG pElement = (PULONG)pVec[id]->pVecMem + elementPos;
				return pElement;
			}

			case TYPE_BOOLEAN:
			{
				PBOOLEAN pElement = (PBOOLEAN)pVec[id]->pVecMem + elementPos;
				return pElement;
			}
		}
	}
	else
	{
		//Get first UNICODE_STRING Element
		PUNICODE_STRING pFirstElement = (PUNICODE_STRING)pVec[id]->pVecMem;
		USHORT lastSize = pFirstElement->MaximumLength;
		ULONG currentSize = 0;
		PUNICODE_STRING pCurrentElement = NULL;

		if (index > pVec[id]->elementCount)
			return NULL; //Index not in range

		if (index == 1)
			return pFirstElement;

		for (USHORT i = 1; i < pVec[id]->elementCount; ++i) //Start at index 2
		{
			currentSize += lastSize;
			pCurrentElement = (PUNICODE_STRING)pVec[id]->pVecMem + currentSize;
			lastSize = pCurrentElement->MaximumLength;

			//If requested element found
			if (index == i)
				break;
		}

		return pCurrentElement;
	}
}

void vector_sort(ULONG id)
{
	if (pVec[id]->vectorType != TYPE_UNICODE_STRING)
	{
		switch (pVec[id]->vectorType)
		{
			case TYPE_ULONG:
			{
				PULONG currentElement = 0;
				PULONG lastElement = 0;

				for (USHORT i = 0; i < pVec[id]->elementCount; ++id)
				{
					//Get current element in vector
					if (i == 1)
					{
						lastElement = (PULONG)pVec[id]->pVecMem; //First Element
						continue;

					}
					else
					{
						currentElement = (PULONG)pVec[id]->pVecMem + pVec[id]->sizeElement * i;

						//Nullptr checking
						if (!currentElement || !lastElement)
							continue;

						if (*currentElement < *lastElement) //If current element is smaler than last element
						{
							//Replace last element with current and set last to current pos
							ULONG temp = *lastElement;
							*lastElement = *currentElement;
							*currentElement = temp;
						}
					}
				}
				break;
			}

			case TYPE_BOOLEAN:
			{
				pVec[vecID]->vectorType = TYPE_BOOLEAN;
				pVec[vecID]->sizeElement = sizeof(BOOLEAN);
				break;
			}
		}
	}
}