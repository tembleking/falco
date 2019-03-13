/*
Copyright (C) 2013-2019 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include "overflow.h"

overflow_mgr::overflow_mgr()
	: m_num_overflows(0),
	  m_inspector(NULL),
	  m_outputs(NULL),
	  m_next_check_ts(0)
{
}

overflow_mgr::~overflow_mgr()
{
}

void overflow_mgr::init(sinsp *inspector,
			falco_outputs *outputs,
			std::set<action> &actions,
			double rate,
			double max_tokens)
{
	m_inspector = inspector;
	m_outputs = outputs;
	m_actions = actions;
	m_bucket.init(rate, max_tokens);

	m_inspector->get_capture_stats(&m_last_stats);
}

bool overflow_mgr::process_event(sinsp_evt *evt)
{
	if(m_next_check_ts == 0)
	{
		m_next_check_ts = evt->get_ts() + ONE_SECOND_IN_NS;
	}

	if(m_next_check_ts < evt->get_ts())
	{
		scap_stats stats, delta;

		m_next_check_ts = evt->get_ts() + ONE_SECOND_IN_NS;

		m_inspector->get_capture_stats(&stats);

		// NOTE: only computing delta for interesting stats (evts/drops)
		delta.n_evts = stats.n_evts - m_last_stats.n_evts;
		delta.n_drops = stats.n_drops - m_last_stats.n_drops;

		m_last_stats = stats;

		if(delta.n_drops > 0)
		{
			m_num_overflows++;

			// There were new drops in the last second. If
			// the token bucket allows, perform actions.
			if(m_bucket.claim(1, evt->get_ts()))
			{
				m_num_actions++;

				return perform_actions(evt->get_ts(), delta);
			}
			else
			{
				falco_logger::log(LOG_DEBUG, "Kernel buffer overflow but token bucket depleted, skipping actions");
			}
		}
	}

	return true;
}

void overflow_mgr::print_stats()
{
	fprintf(stderr, "Kernel buffer overflow monitoring:\n");
	fprintf(stderr, "   - kernel buffer full: %lu occurrences\n", m_num_overflows);
	fprintf(stderr, "   - num times actions taken: %lu\n", m_num_actions);
}

bool overflow_mgr::perform_actions(uint64_t now, scap_stats &delta)
{
	std::string rule = "Falco internal: kernel buffer overflow";
	std::string msg = rule + ". " + std::to_string(delta.n_drops) + " system calls dropped in last second.";

	std::map<std::string,std::string> output_fields;

	output_fields["n_evts"] = std::to_string(delta.n_evts);
	output_fields["n_drops"] = std::to_string(delta.n_drops);

	for(auto &act : m_actions)
	{
		switch(act)
		{
		case ACT_IGNORE:
			break;

		case ACT_LOG:
			falco_logger::log(LOG_ERR, msg);
			break;

		case ACT_ALERT:
			m_outputs->handle_msg(now,
					      falco_outputs::PRIORITY_CRITICAL,
					      msg,
					      rule,
					      output_fields);
			break;

		case ACT_EXIT:
			falco_logger::log(LOG_CRIT, msg);
			falco_logger::log(LOG_CRIT, "Exiting.");
			return false;
			break;

		default:
			falco_logger::log(LOG_ERR, "Ignoring unknown action " + std::to_string(int(act)));
			break;
		}
	}

	return true;
}
