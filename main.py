from helpers.load_input import load
from make_certs.generate2 import Authority


def recurse(authorities):

    def wrapped(authority,_type,parent=None):
        x = Authority(authority,_type,parent)
        parentDN = x.parent.DN if isinstance(x.parent, Authority) else ''
        print('DN: {}, type: {}, Parent: {}'.format(x.DN, _type, parentDN))


        if hasattr(x, 'nodes'):
            for item in x.nodes:
                wrapped(item,'node',x)

        if hasattr(x, 'authorities'):
            for item in x.authorities:
                wrapped(item,'sign',x)

    for authority in authorities:
        wrapped(authority,'root')


if __name__ == '__main__':
    authority_tree = load("input.yml")
    recurse(authority_tree)
