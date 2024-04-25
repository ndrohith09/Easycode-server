from typing import List

from loguru import logger
from rply import ParserGenerator

from abstract_syntax_tree.base import Expression, Print
from abstract_syntax_tree.blocks import MainBlock, ProgramBlock
from .atom_parser import AtomParser
from .expression_parser import ExpressionParser
from .flow_parser import ConditionalParser, LoopParser
from .function_parser import FunctionParser
from .operation_parser import BinaryLogicalOperationsParser, BinaryMathOperationsParser
from .print_parser import PrintParser
from .statement_parser import StatementParser
from .variable_parser import VariableParser


class ParserBase:
    def __init__(self, tokens: List[str]):
        self.pg = ParserGenerator(
            tokens=tokens,
            precedence=[
                ("left", ["NOOP"]),
                ("left", ["LOGICOP"]),
                ("left", ["MATHOP"]),
                ("left", ["SUM", "SUB"]),
                ("left", ["MUL", "DIV", "MOD"]),
            ],
        )

        self.parsers = [
            StatementParser(),
            ExpressionParser(),
            BinaryMathOperationsParser(),
            BinaryLogicalOperationsParser(),
            PrintParser(),
            VariableParser(),
            AtomParser(),
        ]

    def parse(self):
        pass

    def init_parsers(self):
        
        '''
        Initialize all parsers. 
        add all parsers to the parser generator.
        '''

        '''
        We will be checking the statement for each parser.
        '''
        for parser in self.parsers: 
            parser.parse(self.pg)

        @self.pg.error
        def error(token):
            raise ValueError(token)

    def get_parser(self):

        """builds and returns parser"""
        return self.pg.build()


class ProgramParser(ParserBase):
    def __init__(self, tokens: List[str]) :
        super().__init__(tokens)
        self.parsers += [
            ConditionalParser(),
            LoopParser(),
            FunctionParser(),
        ]

    def parse(self):
        @self.pg.production("program : functions main")
        def program(p):
            return ProgramBlock(p[0], p[1])

        @self.pg.production("main : PGM_START statements PGM_END")
        def main(p):
            logger.debug("Parser --> main")
            return MainBlock(p[1])

        self.init_parsers()


class LineParser(ParserBase):
    def __init__(self, tokens: List[str]):
        super().__init__(tokens)

    def parse(self):
        @self.pg.production("statement : PRINT printexprs SEMI_COLON")
        def print_stmt(p):
            return Print(p[1])

        @self.pg.production("statement : expression SEMI_COLON")
        def expr_stms(p):
            return Expression(p[0])

        self.init_parsers()