# Tennis Stats Tracker

Welcome! This repo contains a mini project I completed to learn about RestAPI's.

The intention was to create a backend for a tennis app using Python, Flask, SQLAlchemy and Marshmallow. I used JWT for tokenization and tested all endpoints using Postman.

The app is not hosted anywhere and a randomly generated secret key is used. For good practice, please generate a new secret key before using.

## Functionality
The backend supports the following functionality:
* Create users with tokenized login/logout capability
* Create friendships between users
* Store match data (summative data and point-by-point)
* Generate player/match stats

## Data
I use an SQLAlchemy database with the following tables.

|    User    |     |
|:----------:|:---:|
|    id      | Int |
| username   |String|
| first_name |String|
|  surname   |String|
|  password  |String|
|   email    |String|

| Friendship |                |
|:-----------|:--------------:|
| friendship_id |       Int       |
| requesterId   |       Int       |
| addresseeId   |       Int       |
| statusCode    |     String     |
| statusSpecifierId |    Int     |

|   Match    |                 |
|:-----------|:---------------:|
| match_id    |       Int        |
| player_1_id |       Int        |
| player_2_id |       Int        |
| time_stamp  |       Date       |
| winner      |       Int        |
| status      |     String      |

|  Points    |                  |
|:-----------|:-----------------:|
| point_id     |       Int        |
| match_id     |       Int        |
| point_num    |       Int        |
| server_id    |       Int        |
| receiver_id  |       Int        |
| server_sets  |       Int        |
| receiver_sets|       Int        |
| server_games |       Int        |
| receiver_games |     Int        |
| server_score |      String     |
| receiver_score |    String     |
| first_serve_outcome |String |
| second_serve_outcome |String|
| winner_id |          Int         |

