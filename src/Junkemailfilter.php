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
        $this->configBase = 'parsers.' . $reflect->getShortName();

        Log::info(
            get_class($this) . ': Received message from: ' .
            $this->parsedMail->getHeader('from') . " with subject: '" .
            $this->parsedMail->getHeader('subject') . "' arrived at parser: " .
            config("{$this->configBase}.parser.name")
        );

        $events = [ ];

        $this->feedName = 'default';

        if (!$this->isKnownFeed()) {
            return $this->failed(
                "Detected feed {$this->feedName} is unknown."
            );
        }

        if (!$this->isEnabledFeed()) {
            return $this->success($events);
        }

        if ($this->arfMail === false) {
            return $this->failed("Detected feed '{$this->feedName}' should be ARF, but received plain message.");
        }

        preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/', $this->arfMail['report'], $regs);
        $report = array_combine($regs[1], $regs[2]);

        $report = $this->applyFilters($report);

        if ($report['Feedback-Type'] != 'abuse') {
            return $this->failed(
                "Unabled to detect the report type from this notifier"
            );
        }

        $fields['evidence'] = $this->arfMail['evidence'];

        $event = [
            'source'        => config("{$this->configBase}.parser.name"),
            'ip'            => $fields['Source-IP'],
            'domain'        => false,
            'uri'           => false,
            'class'         => config("{$this->configBase}.feeds.{$this->feedName}.class"),
            'type'          => config("{$this->configBase}.feeds.{$this->feedName}.type"),
            'timestamp'     => strtotime($report['Received-Date']),
            'information'   => json_encode($report),
        ];

        $events[] = $event;

        return $this->success($events);
    }
}
