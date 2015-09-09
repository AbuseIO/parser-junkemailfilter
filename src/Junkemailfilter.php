<?php

namespace AbuseIO\Parsers;

use Ddeboer\DataImport\Reader;
use Ddeboer\DataImport\Writer;
use Ddeboer\DataImport\Filter;
use Log;
use ReflectionClass;

class Junkemailfilter extends Parser
{
    public $parsedMail;
    public $arfMail;

    /**
     * Create a new Blocklistde instance
     */
    public function __construct($parsedMail, $arfMail)
    {
        $this->parsedMail = $parsedMail;
        $this->arfMail = $arfMail;
    }

    /**
     * Parse attachments
     * @return Array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        // Generalize the local config based on the parser class name.
        $reflect = new ReflectionClass($this);
        $configBase = 'parsers.' . $reflect->getShortName();

        Log::info(
            get_class($this) . ': Received message from: ' .
            $this->parsedMail->getHeader('from') . " with subject: '" .
            $this->parsedMail->getHeader('subject') . "' arrived at parser: " .
            config("{$configBase}.parser.name")
        );

        $feedName = 'default';

        if ($this->arfMail === false) {
            return $this->failed("Detected feed '{$feedName}' should be ARF, but received plain message.");
        }

        $events = [ ];

        preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/', $this->arfMail['report'], $regs);
        $fields = array_combine($regs[1], $regs[2]);

        $columns = array_filter(config("{$configBase}.feeds.{$feedName}.fields"));
        if (count($columns) > 0) {
            foreach ($columns as $column) {
                if (!isset($fields[$column])) {
                    return $this->failed(
                        "Required field ${column} is missing in the report or config is incorrect."
                    );
                }
            }
        }

        if ($fields['Feedback-Type'] != 'abuse') {
            return $this->failed(
                "Unabled to detect the report type from this notifier"
            );
        }

        if (empty(config("{$configBase}.feeds.{$feedName}"))) {
            return $this->failed("Detected feed '{$feedName}' is unknown.");
        }

        if (config("{$configBase}.feeds.{$feedName}.enabled") !== true) {
            return $this->success($events);
        }

        $fields['evidence'] = $this->arfMail['evidence'];

        $event = [
            'source'        => config("{$configBase}.parser.name"),
            'ip'            => $fields['Source-IP'],
            'domain'        => false,
            'uri'           => false,
            'class'         => config("{$configBase}.feeds.{$feedName}.class"),
            'type'          => config("{$configBase}.feeds.{$feedName}.type"),
            'timestamp'     => strtotime($fields['Received-Date']),
            'information'   => json_encode($fields),
        ];

        $events[] = $event;

        return $this->success($events);
    }
}
