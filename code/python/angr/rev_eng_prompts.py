#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Apr 20 01:48:33 2024

@author: xdoestech
"""

from typing import List

from langchain.chains import LLMChain
from langchain.output_parsers import PydanticOutputParser
from langchain_core.prompts import PromptTemplate
from pydantic import BaseModel, Field
from langchain.retrievers.multi_query import MultiQueryRetriever

# Build a sample vectorDB
from langchain_community.document_loaders import WebBaseLoader
from langchain_community.vectorstores import Chroma
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
import os

from view_file_info import get_file_info, get_strings, is_elf_file, disassemble,readelf_analysis
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain.prompts import PipelinePromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

goal_template = """
We are analyzing a binary file in order to understand its functionality. 
We will be following a static analysis procedure.
"""
analyze_strings = """
Analyze the output of the strings command below. 
Explain which strings may be important or useful for reverse engineering. 
"""
get_ouputmessages_strings = """
List all of the potential ouput messages from the strings output. 
Provide an explanation for why they are potential output messages.
"""
get_other_strings = """
List all other strings that may hold some importance. 
Do not include symbol table, elf sections, or metadata. 
Provide an explanation for why the strings you chose may hold some importance.
"""
strings_template = """
You will analyze the output of the strings command below and explain which strings may be important or useful for reverse engineering.
 List all of the potential ouput messages from the strings output. 
 Provide an explanation for why they are potential output messages.
 List all other strings that may hold some importance. 
 Do not include symbol table, elf sections, or metadata. 
 Provide an explanation for why the strings you chose may hold some importance.
"""
full_strings_template = """
{goal}

{analysis}

{start}
"""
start_template = """
STRING OUTPUT BELOW:
{strings}
"""

analyze_disassembled_detect_obfuscation = """
Based on the provided disassembled binary code, perform the following analysis:
1. Identify any unusual patterns or unconventional coding practices that deviate from standard programming techniques or conventions. These could include:
   - Convoluted control flow (e.g., unnecessary jumps, redundant instructions)
   - Obfuscated data structures or variable encodings
   - Usage of anti-debugging or anti-virtualization techniques
2. Look for sections of code that seem designed to hinder reverse engineering efforts, such as:
   - Code flattening or control flow obfuscation techniques
   - Encrypted or encoded code sections
   - Anti-disassembly or anti-tampering mechanisms
3. If any obfuscation or anti-analysis techniques are detected, provide an analysis of their purpose and potential impact on the reverse engineering process. This could include:
   - Explaining how the technique works and what it aims to achieve
   - Assessing the difficulty of bypassing or analyzing the obfuscated code
   - Identifying potential vulnerabilities or weaknesses in the obfuscation technique
Respond with a detailed analysis, including specific examples from the code if applicable. If no obfuscation or anti-analysis techniques are detected, explicitly state that the code appears to be unobfuscated based on your analysis.

Example responses:
- "The code does not appear to be obfuscated or employ any anti-analysis techniques based on the provided disassembly."
- "The binary seems to be packed or encrypted, making it difficult to analyze the code directly. Further unpacking or decryption steps may be required."
- "The code appears to use control flow flattening techniques, likely to hinder disassembly and analysis. This obfuscation technique aims to... [provide detailed analysis]"
"""
 
analyze_disassembled_flow = """
Based on the provided disassembled binary code, perform the following analysis:
1. Identify the control flow structures present in the code, such as loops (e.g., `jmp`, `loop`), conditional statements (e.g., `je`, `jne`), and function calls (e.g., `call` instructions).
2. Examine the data structures being used, which could include arrays, strings (e.g., sequences of characters), or structures (e.g., structs or records).
3. Develop an understanding of how the program's execution flow works, considering the identified control flow structures and potential data dependencies.
4. Highlight any areas of interest, such as unusual control flow patterns, potential vulnerabilities (e.g., buffer overflows, integer overflows), or code obfuscation techniques.
Respond with a dictionary where the keys are function names (e.g., `main`, `obfuscate_password`, `check_password`), and the values are strings describing the function's importance, control flow characteristics, data structures used, and any other relevant observations.
For example:
{
    "main": "Appears to be the entry point, calls `check_password` function, uses conditional jumps based on the return value",
    "obfuscate_password": "Modifies a string (likely a password) using an XOR operation, loops through string characters",
    "check_password": "Compares a provided string with an obfuscated password, uses string manipulation functions"
}
"""

confirm_disassembled_retreival = """
<|begin_of_text|><|start_header_id|>system<|end_header_id|>
Confirm that the retrieved disassembled binary code contains the identified important functions. 
Provide a JSON response with a key 'filename' and a value of either 'is relevant' or 'is not relevant'. 

Here is the retrieved disassembled binary code: \n\n {document} \n\n
<|eot_id|><|start_header_id|>assistant<|end_header_id|>
"""