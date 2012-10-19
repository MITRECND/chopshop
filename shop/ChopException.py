#! /usr/bin/env python

class ChopException(BaseException):
    pass


class ChopUiException(ChopException):
    pass


class ChopLibException(ChopException):
    pass

