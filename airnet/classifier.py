# AIRNET PROJECT
# Copyright (c) 2017 Messaoud AOUADJ, Emmanuel LAVINAL, Mayoro BADJI

# TODO: remove default drop rule in __add__
# TODO: description for __rshift__

import copy

class Rule(object):
    """ defines an edge logical control rule """

    def __init__(self, m, t, acts):
        """ an edge rule has three attributes
            - a match
            - a label
            - actions
        """
        self.match = m
        self.label = t
        self.actions = acts

    def __str__(self):
        """ returns a correct presentation
            of an edge rule object """
        return "{} -- {} -- {}".format(self.match,
                                self.label,self.actions)

class FabricRule(object):
    """ defines a fabric logical control rule """

    def __init__(self, f, acts, via_list):
        """ a fabric rule has three attributes
            - a flow
            - actions
            - a via_list (when datamachines are involved)
        """
        self.flow = f
        self.actions = acts
        self.via_list = via_list

    def __str__(self):
        """ returns a correct presentation
            of a fabric rule object """
        return "{} -- {} -- {}".format(self.flow,
                str(self.actions), str(self.via_list))

class Classifier(object):
    """ an edge classifier stores a list of edge rules
        where the order in which those rules are stored
        defines the priorities between them """

    def __init__(self, rules=[]):
        """ a classifier has a list of rules """
        self.rules = list(rules)

    def append(self, item):
        """ adds a new element to the edge classifier """
        # the new element to add can be an edge rule
        if isinstance(item, Rule):
            self.rules.append(item)
        # or another classifier
        elif isinstance(item, Classifier):
            self.rules.extend(item.rules)
        else:
            raise TypeError

    def getLogRules(self):
        """ returns the rules (string format)
            stored in the classifier """
        str_Rules = ""
        for rule in self.rules:
            str_Rules = str_Rules + str(rule) + "\n"
        return str_Rules

    def getNbRules(self):
        return len(self.rules)

    def __add__(c1, c2):
        """ adds in a new classifier rules generated by
            intersections between c1 and c2 contents """
        from language import identity, drop, forward, DataFctPolicy

        def _cross(r1, r2):
            """ creates a new rule when there is an intersection
                between r1 and r2 """

            # check intersection in match fields
            intersection = r1.match.intersec(r2.match)

            if intersection != drop:
                # there is an intersection here
                label = identity
                # if both r1 and r2 have labels
                if r1.label is not identity and r2.label is not identity:
                    # use the more specific one
                    if r1.match.covers(r2.match):
                        label = r2.label
                    elif r2.match.covers(r1.match):
                        label = r1.label
                    else:
                        part1 = str(r1.label)
                        part2 = str(r2.label)
                        errorMsg = "Tag intersection error: " + part1 + " \
                                    and " + part2
                        raise AssertionError(errorMsg)
                else:
                    if r1.label is identity:
                        label = r2.label
                    else:
                        label = r1.label

                actions = set()
                # trying here to handle drop and forward intersection bug
                if r1.match is not identity and r2.match is not identity:
                    # there are no covering between rules here
                    if r1.match.covers(r2.match) == False and r2.match.covers(r1.match) == False :
                        # if one of those 2 rules jas a drop action
                        if len(r1.actions)==0 or len(r2.actions)==0:
                            # the intersection rule got the drop action
                            return Rule(intersection,label,actions)

                # if they have the same forward action, we use only one
                # we assume that they have the same forward destination
                contain_forward = False
                # add all actions from r1
                for a1 in r1.actions:
                    if isinstance(a1, forward):
                        contain_forward = True
                    actions.add(a1)

                # then add all actions from r2
                for a2 in r2.actions:
                    if isinstance(a2, forward) and not contain_forward:
                        # we get here when there is no forward action in r1
                        actions.add(a2)
                        """
                        elif isinstance(a2, DataFctPolicy):
                            nwFct_added = False
                            for act in actions:
                                if isinstance(act, DataFctPolicy):
                                    nwFct_added = True
                                    act.add_parallel_fct(a2)
                            if not nwFct_added:
                                actions.add(a2)
                        """
                    elif not isinstance(a2, forward):
                        actions.add(a2)
                    else:
                        return None
                return Rule(intersection, label, actions)
            else:
                return None

        # the new classifier
        c3 = Classifier()
        # cross each rule in c1 with all rules in c2
        for r1 in c1.rules:
            for r2 in c2.rules:
                # check intersection between those two rules
                crossed_r = _cross(r1, r2)
                if crossed_r:
                    # if there is one, in crossed_r, we have an intersection rule
                    # generated by the _cross function
                    # add it to the new classifier
                    c3.append(crossed_r)
                    # sachant que dans chaque classifier y a (identity, identity, set())
                    # donc toutes les regles des deux classifier seront rajoute
        if len(c3.rules) == 0:
            # if there is no intersection between c1 and c2 rules
            # add a default drop rule
            c3.append(Rule(identity, identity, set()))
        else:
            # there is at least one intersection --> optimize
            c3 = c3.optimize()
        return c3

    def __rshift__(c1, c2):
        from language import identity, modify, forward, tag,\
                             drop, match, DataFctPolicy,\
                             DynamicPolicy, NetworkFunction

        def _sequence_actions(a1, as2):
            if isinstance(a1, DataFctPolicy):
                a1.add_seq_actions(as2)
                return {a1}
            elif a1 == identity:
                return copy.copy(as2)
            elif isinstance(a1, modify):
                new_actions = set()
                for a2 in as2:
                    # DataFct or DyControl
                    if isinstance(a2, NetworkFunction):
                        new_actions.add(a1)
                        new_actions.add(a2)
                    elif isinstance(a2, forward):
                        new_actions.add(a1)
                        new_actions.add(a2)
                    elif a2 == identity:
                        new_actions.add(a1)
                    elif isinstance(a2, modify):
                        new_a1 = modify(**a1.map.copy())
                        new_a1.map.update(a2.map)
                        new_actions.add(new_a1)
                    else:
                        raise TypeError
                return new_actions
            elif isinstance(a1, forward) or isinstance(a1, DynamicPolicy):
                # no right shift after a forward or a dynamic control function
                raise AssertionError
            else:
                raise TypeError

        def _commute_test(act, pkts):
            """
            given a test b and an action p, return a test
            b' such that p >> b == b' >> p.
            e.g. (match1, tag1, actions1) >> (match2, tag2, actions2)
            match2 don't apply directly on match1
            but apply on it after the execution of actions1
            """
            # if act == identity or isinstance(act, tag) --> deleted
            if act == identity:
                return pkts
                """
                elif isinstance(act, DataFctPolicy):
                return identity
                """
            elif isinstance(act, modify):
                new_match_dict = {}
                if pkts == identity:
                    return identity
                elif pkts == drop:
                    return drop
                for f, v in pkts.map.iteritems():
                    if f in act.map and act.map[f] == v:
                        continue
                    elif f in act.map and act.map[f] != v:
                        return drop
                    else:
                        new_match_dict[f] = v
                if len(new_match_dict) == 0:
                    return identity
                return match(**new_match_dict)
            elif isinstance(act, forward):
                # no actions after a forward action !
                raise AssertionError
            else:
                raise TypeError

        def _cross_act(r1, act, r2):
            # match
            m = r1.match.intersec(_commute_test(act, r2.match))
            # label
            # seq composition: if the second rule has a label, use it!
            label = r1.label
            if r2.label != identity:
                label = r2.label
            # actions
            actions = _sequence_actions(act, r2.actions)
            if m == drop:
                return None
            else:
                return Classifier([Rule(m, label, actions)])

        def _cross(r1, r2):
            """ crosses r1 and r2 and returns a partial classifier """
            # the partial classifier
            c = None

            for act in r1.actions:
                cross = _cross_act(r1, act, r2)
                if c is None:
                    c = cross
                elif not cross is None:
                    c_tmp = c + cross
                    c_tmp.append(c)
                    c_tmp.append(cross)
                    c = c_tmp
                    c.optimize()
            return c

        # the new classifiers
        c3 = Classifier()
        # cross each non-drop rule in c1 with all rules in c2
        for r1 in c1.rules:
            if len(r1.actions) == 0:
                c3.append(r1)
            else:
                for r2 in c2.rules:
                    c_tmp = _cross(r1, r2)
                    if not c_tmp is None:
                        c3.append(c_tmp)
        c3.optimize()
        return c3

    def optimize(self):
        """ optimizes the classifier rules """
        return self.remove_shadowed_cover_single()

    def remove_shadowed_cover_single(self):
        """ removes rules that are covered by another one(s)
            in the current classifier """
        opt_c = Classifier()
        for r in self.rules:
            # if a current rule is not covered by any other one
            if not reduce(lambda acc, new_r: acc or
                          new_r.match.covers(r.match),
                          opt_c.rules,
                          False):
                # add it to the optimized classifier
                opt_c.rules.append(r)
        return opt_c

class FabricClassifier(object):
    """ a fabric classifier stores a list of fabric rules
        where the order in which those rules are stored
        defines the priorities between them """

    def __init__(self, rules=[]):
        """ a fabric classifier has a list of rules """
        self.rules = list(rules)

    def append(self, item):
        """ adds a new element to the fabric classifier """
        # the new element to add can be a fabric rule
        if isinstance(item, FabricRule):
            self.rules.append(item)
        # or another fabric classifier
        elif isinstance(item, FabricClassifier):
            self.rules.extend(item.rules)
        else:
            raise TypeError

    def getLogRules(self):
        """ returns the rules stored in the fabric classifier """
        str_Rules = ""
        for rule in self.rules:
            str_Rules = str_Rules + str(rule) + "\n"
        return str_Rules

    def getNbRules(self):
        return len(self.rules)

    def __add__(c1, c2):
        """ merges c1 and c2 contents in a new FabricClassifier """
        c3 = FabricClassifier()
        c3.append(c1)
        c3.append(c2)
        return c3

    def __rshift__(c1, c2):
        from language import identity
        # The resulting classifier
        c3 = FabricClassifier()
        # for each rule in the first classifier
        for r1 in c1.rules:
            new_actions = set()
            via_list = list()
            # for each rule rule in the second one
            for r2 in c2.rules:
                flow = r1.flow
                for act1 in r1.actions:
                    if act1 != identity:
                        new_actions.add(act1)
                for act2 in r2.actions:
                    if act2 != identity:
                        new_actions.add(act2)
                for dm in r1.via_list:
                    via_list.append(dm)
                for dm in r2.via_list:
                    via_list.append(dm)

                c3.append(FabricRule(flow, new_actions, via_list))
        return c3
