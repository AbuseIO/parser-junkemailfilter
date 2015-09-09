<?php

return [
    'parser' => [
        'name'          => 'JunkEmailFilter',
        'enabled'       => true,
        'sender_map'    => [
            '/@junkemailfilter.com/',
        ],
        'body_map'      => [
            //
        ],
    ],

    'feeds' => [
        'default' => [
            'class'     => 'SPAM',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source-IP',
                'Feedback-Type',
                'Received-Date',
            ],
        ],

    ],
];
