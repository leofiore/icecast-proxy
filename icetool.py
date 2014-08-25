#!/usr/bin/env python
import sys
import getpass
from database import SQLManager, User, Mount
import bcrypt


def cmd_users(action, username=None, password=None):

    with SQLManager() as session:
        if action == "list":
            print("Current Users:")
            for row in session.query(User):
                print("[{}] {}".format(row.privileges, row.user))

        elif action == "del":
            if not username or len(username) < 3:
                print("Please provide a valid username")
                sys.exit(0)
            yes = raw_input(
                "Are you sure you want to delete user {}? (Yes/no): ".format(
                    username
                ))
            if yes.lower().strip() == "yes":
                session.query(User).filter(User.user==username).delete()
                session.commit()

        elif action == "add":
            while not username or len(username) < 3:
                username = raw_input("Please provide a username (3 chars min): ")
            while not password or len(password) < 5:
                password = getpass.getpass("please provide a password (5 chars min): ")
            for row in session.query(User).filter(User.user==username):
                print(
                    "A username with that name exists already. "
                    "Please provide another username or use the "
                    "command 'users del' to delete and readd."
                )
            salt = bcrypt.gensalt()
            cryptpw = bcrypt.hashpw(password, salt)
            session.add(User(
                user=username,
                password=cryptpw,
                privileges=1))
            session.commit()


def cmd_routes(action, *args):

    proto = ['http', 'xa', 'icy']
    with SQLManager() as session:
        if action == "list":
            source =  args and args[0] or None
            if source:
                routes = session.query(Mount).filter(Mount.source==source).all()
            else:
                routes = session.query(Mount).order_by(Mount.source).all()
            routestr = " {source: <17} | {destination: <39} | {format: <17} "
            print(routestr.format(
                source="proxy mountpoint",
                destination="destination server",
                format="format"
            ))
            print("-" * 80)
            for route in routes:
                print(routestr.format(
                    source=route.source,
                    destination="".join(
                        [proto[int(route.protocol)], '://',
                        route.host, ":",
                         str(route.port),
                         route.mount]),
                    format=route.format
                ))

        elif action == "add":
            if not args:
                print(
                    "no arguments provided.\n\n"
                    "Syntax: routes add "
                    "<proxy mount> <server> <port> <mount> <protocol> <format>")
                sys.exit(1)
            source, host, port, mount, protocol, format = args
            user = None
            password = None

            while not user or not len(user.strip()):
                user = raw_input("enter the server's username: ")
            while not password or not len(password.strip()):
                password = getpass.getpass("enter the password for %s: " % user)

            route = Mount(
                source=source,
                host=host,
                port=int(port),
                password=password,
                format=format,
                protocol=str(proto.index(protocol)),
                mount=mount,
                user=user)
            session.add(route)
            session.commit()

        elif action == "del":
            sys.exit(1) #TODO


if __name__ == "__main__":
    args = sys.argv[1:]

    if args[0] == "users":
        cmd_users(*args[1:])
    elif args[0] == "routes":
        cmd_routes(*args[1:])
    elif args[0] == "status":
        print("not implemented")
