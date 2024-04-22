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